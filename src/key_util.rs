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

pub fn get_public_key_from_secret_key(secret_key: SecretKey, secp: &Secp256k1<All>) -> PublicKey {
    PublicKey::from_secret_key(&secp, &secret_key)
}

#[cfg(test)]
mod tests {
    use crate::key_util::get_public_key_from_secret_key;
    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::{CheckedMul, One};
    use secp256k1::{Secp256k1, SecretKey};
    use std::str::FromStr;

    #[test]
    fn verify_negation() {
        let secp = Secp256k1::new();
        let private_key =
            SecretKey::from_str("000000000000000000000000000000000000000000000000f7051f27b09112d4")
                .unwrap();
        let public_key = get_public_key_from_secret_key(private_key, &secp);
        assert_eq!(
            public_key.serialize(),
            hex!("03100611c54dfef604163b8358f7b7fac13ce478e02cb224ae16d45526b25d9d4d")
        );

        let negated_private_key = private_key.negate();
        assert_eq!(
            negated_private_key.secret_bytes(),
            hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03ac8cd3f651fa52e6d")
        );

        let negated_public_key = public_key.negate(&secp);
        assert_eq!(
            negated_public_key.serialize(),
            hex!("02100611c54dfef604163b8358f7b7fac13ce478e02cb224ae16d45526b25d9d4d")
        );

        assert_eq!(private_key, negated_private_key.negate());
        assert_eq!(public_key, negated_public_key.negate(&secp));

        let x = public_key.x_only_public_key();
        let uint = BigUint::from_bytes_be(&x.0.serialize());
        let beta = hex!("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
        let beta = BigUint::from_bytes_be(&beta);
        let p = BigUint::from_bytes_be(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
        ));
        let result = uint.checked_mul(&beta).unwrap().modpow(&BigUint::one(), &p);
        assert_eq!(
            result.to_str_radix(16),
            "792bfa55bf659967951b21060c05c250cd261ec3ea02704815bfb1c5ccc800fd"
        )
    }
}
