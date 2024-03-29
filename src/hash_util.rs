use primitive_types::H160;
use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

pub fn hash_public_key(public_key: &PublicKey) -> (H160, H160) {
    let compressed = Ripemd160::digest(&Sha256::digest(&public_key.serialize()));
    let uncompressed = Ripemd160::digest(&Sha256::digest(&public_key.serialize_uncompressed()));
    (
        H160::from_slice(&compressed.as_slice()),
        H160::from_slice(&uncompressed.as_slice()),
    )
}
