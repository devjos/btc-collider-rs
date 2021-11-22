use secp256k1::{All, PublicKey, Secp256k1, SecretKey};

pub fn get_public_key_from_private_key_primitive(key: u128, secp: &Secp256k1<All>) -> PublicKey {
    let mut k: [u8; 32] = [0; 32];
    k[16..].copy_from_slice(&key.to_be_bytes());
    get_public_key_from_private_key(k, secp)
}

pub fn get_public_key_from_private_key_vec(key: Vec<u8>, secp: &Secp256k1<All>) -> PublicKey {
    let mut num: [u8; 32] = [0; 32];
    let key_slice = key.as_slice();

    let start_index = 32 - key_slice.len();
    num[start_index..32].copy_from_slice(key_slice);
    get_public_key_from_private_key(num, secp)
}

pub fn get_public_key_from_private_key(key: [u8; 32], secp: &Secp256k1<All>) -> PublicKey {
    let secret_key = SecretKey::from_slice(&key).expect("32 bytes, within curve order");
    PublicKey::from_secret_key(&secp, &secret_key)
}
