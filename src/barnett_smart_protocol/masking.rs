use crate::barnett_smart_protocol::Card;
use crate::error::CardProtocolError;
use crate::Mask;

use ark_ec::CurveGroup;
use proof_base::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};

impl<C: CurveGroup> Mask<C::ScalarField, ElGamal<C>> for Card<C> {
    fn mask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        r: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let ciphertext = ElGamal::<C>::encrypt(pp, shared_key, self, r)?;
        Ok(ciphertext)
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
    use ark_std::rand::thread_rng;

    // Choose elliptic curve setting
    type Curve = ark_bls12_381::G1Projective;
    type Scalar = ark_bls12_381::Fr;

    // Instantiate concrete type for our card protocol
    type CardProtocol = barnett_smart_protocol::DLCards<Curve>;
    type CardParameters = barnett_smart_protocol::Parameters<Curve>;
    type PublicKey = barnett_smart_protocol::PublicKey<Curve>;
    type SecretKey = barnett_smart_protocol::PlayerSecretKey<Curve>;

    type Card = barnett_smart_protocol::Card<Curve>;
    type MaskedCard = barnett_smart_protocol::MaskedCard<Curve>;

    type MaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

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
    fn test_verify_masking() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);

        let some_card = Card::rand(rng);
        let some_random = Scalar::rand(rng);

        let (masked, masking_proof): (MaskedCard, MaskingProof) =
            CardProtocol::mask(rng, &parameters, &aggregate_key, &some_card, &some_random).unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_mask(
                &parameters,
                &aggregate_key,
                &some_card,
                &masked,
                &masking_proof
            )
        );

        let wrong_masked = MaskedCard::rand(rng);

        assert_eq!(
            CardProtocol::verify_mask(
                &parameters,
                &aggregate_key,
                &some_card,
                &wrong_masked,
                &masking_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }
}
