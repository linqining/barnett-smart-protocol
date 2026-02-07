use crate::barnett_smart_protocol::MaskedCard;
use crate::error::CardProtocolError;
use crate::{Mask, Remask};

use ark_ec::CurveGroup;
use proof_base::homomorphic_encryption::{el_gamal, el_gamal::ElGamal};

impl<C: CurveGroup> Remask<C::ScalarField, ElGamal<C>> for MaskedCard<C> {
    fn remask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        alpha: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let zero = el_gamal::Plaintext::zero();
        let masking_point = zero.mask(pp, shared_key, alpha)?;
        let remasked_cipher = *self + masking_point;

        Ok(remasked_cipher)
    }
}

#[cfg(test)]
mod test {
    use crate::barnett_smart_protocol;
    use crate::BarnettSmartProtocol;

    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, Zero};
    use proof_base::error::CryptoError;
    use proof_base::zkp::proofs::chaum_pedersen_dl_equality;
    use rand::thread_rng;

    // Choose elliptic curve setting
    type Curve = bl::Projective;
    type Scalar = starknet_curve::Fr;

    // Instantiate concrete type for our card protocol
    type CardProtocol = barnett_smart_protocol::DLCards<Curve>;
    type CardParameters = barnett_smart_protocol::Parameters<Curve>;
    type PublicKey = barnett_smart_protocol::PublicKey<Curve>;
    type SecretKey = barnett_smart_protocol::PlayerSecretKey<Curve>;

    type MaskedCard = barnett_smart_protocol::MaskedCard<Curve>;

    type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

    fn setup_players<R: Rng>(
        rng: &mut R,
        parameters: &CardParameters,
        num_of_players: usize,
    ) -> (Vec<(PublicKey, SecretKey)>, PublicKey) {
        let mut players: Vec<(PublicKey, SecretKey)> = Vec::with_capacity(num_of_players);
        let mut expected_shared_key = PublicKey::zero();

        for i in 0..parameters.n {
            players.push(CardProtocol::player_keygen(rng, &parameters).unwrap());
            expected_shared_key = expected_shared_key + players[i].0
        }

        (players, expected_shared_key)
    }

    #[test]
    fn test_verify_remasking() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);

        let some_masked_card = MaskedCard::rand(rng);
        let some_random = Scalar::rand(rng);

        let (remasked, remasking_proof): (MaskedCard, RemaskingProof) = CardProtocol::remask(
            rng,
            &parameters,
            &aggregate_key,
            &some_masked_card,
            &some_random,
        )
        .unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_remask(
                &parameters,
                &aggregate_key,
                &some_masked_card,
                &remasked,
                &remasking_proof
            )
        );

        let wrong_output = MaskedCard::rand(rng);

        assert_eq!(
            CardProtocol::verify_remask(
                &parameters,
                &aggregate_key,
                &some_masked_card,
                &wrong_output,
                &remasking_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }
}
