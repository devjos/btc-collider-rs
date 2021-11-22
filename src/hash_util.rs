use crate::Output;
use ripemd160::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

pub fn hash_public_key(public_key: &PublicKey) -> ([u8; 20], [u8; 20]) {
    let uncompressed = Ripemd160::digest(&Sha256::digest(&public_key.serialize_uncompressed()));
    let compressed = Ripemd160::digest(&Sha256::digest(&public_key.serialize()));
    (
        get_160_bit_hash(&uncompressed),
        get_160_bit_hash(&compressed),
    )
}

fn get_160_bit_hash(ripemd160: &Output<Ripemd160>) -> [u8; 20] {
    <[u8; 20]>::try_from(ripemd160.as_slice()).unwrap()
}
