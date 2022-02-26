use bech32::u5;
use num_bigint::BigUint;

#[derive(PartialEq)]
pub enum BTCAddressType {
    P2PK,
    P2SH,
    P2WPKH,
    P2WSH,
    MISC,
}

pub fn get_address_type(address: &str) -> BTCAddressType {
    if address.starts_with("1") {
        return BTCAddressType::P2PK;
    } else if address.starts_with("3") {
        return BTCAddressType::P2SH;
    } else if address.starts_with("bc1") {
        let (_hrp, data, _variant) = bech32::decode(address).unwrap();
        let d: Vec<u5> = data;
        if d.len() == 33 {
            return BTCAddressType::P2WPKH;
        } else {
            return BTCAddressType::P2WSH;
        }
    }

    BTCAddressType::MISC
}

pub fn p2wpkh_address_to_160_bit_hash(address: &str) -> [u8; 20] {
    let (_hrp, data, _variant) = bech32::decode(address).unwrap();
    let data: Vec<u5> = data;
    if data.len() != 33 {
        panic!("Cannot read p2wpkh address {}", address);
    }
    let converted: Vec<u8> = data[1..33].iter().map(|e| e.to_u8()).collect();

    let u8 = BigUint::from_radix_be(converted.as_slice(), 32)
        .unwrap()
        .to_bytes_be();
    let mut hash: [u8; 20] = [0; 20];
    let start_index = 20 - u8.len();
    hash[start_index..20].copy_from_slice(&u8);
    hash
}

pub fn p2pk_address_to_160_bit_hash(address: &str) -> [u8; 20] {
    let decoded = bs58::decode(address).into_vec().unwrap();
    if decoded.len() != 25 {
        panic!("Cannot read p2pk address {}", address);
    }

    let mut hash: [u8; 20] = [0; 20];
    hash.copy_from_slice(&decoded[1..21]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_util, key_util};
    use num_traits::Num;
    use parameterized_macro::parameterized;
    use secp256k1::Secp256k1;

    #[test]
    fn can_return_address_type() {
        assert!(BTCAddressType::P2PK == get_address_type("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"));
        assert!(BTCAddressType::P2SH == get_address_type("3N5i3Vs9UMyjYbBCFNQqU3ybSuDepX7oT3"));
        assert!(
            BTCAddressType::P2WPKH
                == get_address_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        );
    }

    #[parameterized(key = {1, 2, 3}, uncompressed_address = {
    "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", //key is 1
    "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m", //key is 2
    "1NZUP3JAc9JkmbvmoTv7nVgZGtyJjirKV1", //key is 3
    }, compressed_address = {
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", //key is 1
    "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP", //key is 2
    "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb", //key is 3
    })]
    fn can_get_hash_from_p2pk(key: u128, uncompressed_address: &str, compressed_address: &str) {
        let public_key =
            key_util::get_public_key_from_private_key_primitive(key, &Secp256k1::new());
        let (hash_from_uncompressed_key, hash_from_compressed_key) =
            hash_util::hash_public_key(&public_key);
        assert_eq!(
            hash_from_uncompressed_key,
            p2pk_address_to_160_bit_hash(uncompressed_address)
        );
        assert_eq!(
            hash_from_compressed_key,
            p2pk_address_to_160_bit_hash(compressed_address)
        );
    }

    #[parameterized(address = {
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", //bech32
    "bc1pm9jzmujvdqjj6y28hptk859zs3yyv78hlz84pm", //bech32m
    }, expected_hash = {
    "751e76e8199196d454941c45d1b3a323f1433bd6",
    "d9642df24c68252d1147b85763d0a284484678f7",
    })]
    fn can_get_hash_from_bech32(address: &str, expected_hash: &str) {
        let actual = p2wpkh_address_to_160_bit_hash(&address);
        let expected = BigUint::from_str_radix(&expected_hash, 16)
            .unwrap()
            .to_bytes_be();

        assert_eq!(expected, actual);
    }
}
