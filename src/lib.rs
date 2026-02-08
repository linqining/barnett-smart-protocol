use crate::error::CardProtocolError;
use ark_ff::{Field};
use proof_base::homomorphic_encryption::HomomorphicEncryptionScheme;

pub mod barnett_smart_protocol;
pub mod error;
pub mod utils;

pub trait Mask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn mask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Remask<Scalar: Field, Enc: HomomorphicEncryptionScheme<Scalar>> {
    fn remask(
        &self,
        pp: &Enc::Parameters,
        shared_key: &Enc::PublicKey,
        r: &Scalar,
    ) -> Result<Enc::Ciphertext, CardProtocolError>;
}

pub trait Reveal<F: Field, Enc: HomomorphicEncryptionScheme<F>> {
    fn reveal(&self, cipher: &Enc::Ciphertext) -> Result<Enc::Plaintext, CardProtocolError>;
}

