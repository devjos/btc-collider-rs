use primitive_types::H160;

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
        let (_hrp, data) = bech32::decode(address)
            .unwrap_or_else(|_| panic!("Invalid bech32 address: {}", &address));
        if data.len() == 20 {
            return BTCAddressType::P2WPKH;
        } else {
            return BTCAddressType::P2WSH;
        }
    }

    BTCAddressType::MISC
}

pub fn p2wpkh_address_to_160_bit_hash(address: &str) -> H160 {
    let (_hrp, data) = bech32::decode(address).expect("Invalid bech32 address");

    let hash: [u8; 20] = data[0..20].try_into().unwrap();
    H160::from(hash)
}

pub fn p2pk_address_to_160_bit_hash(address: &str) -> H160 {
    let decoded = bs58::decode(address).into_vec().unwrap();
    if decoded.len() != 25 {
        panic!("Cannot read p2pk address {}", address);
    }

    H160::from_slice(&decoded[1..21])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_util, key_util};
    use parameterized_macro::parameterized;
    use secp256k1::Secp256k1;
    use std::str::FromStr;

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
        assert!(matches!(
            get_address_type(&uncompressed_address),
            BTCAddressType::P2PK
        ));
        assert!(matches!(
            get_address_type(&compressed_address),
            BTCAddressType::P2PK
        ));

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
    "bc1qqzzcr0x26mm30v5h0r6j3pe4zkjd0hkpv8qglf", //data is only 19 bytes long
    }, expected_hash = {
    "751e76e8199196d454941c45d1b3a323f1433bd6",
    "d9642df24c68252d1147b85763d0a284484678f7",
    "008581bccad6f717b29778f528873515a4d7dec1",
    })]
    fn can_get_hash_from_bech32(address: &str, expected_hash: &str) {
        assert!(matches!(get_address_type(&address), BTCAddressType::P2WPKH));

        let actual = p2wpkh_address_to_160_bit_hash(&address);
        let expected = H160::from_str(expected_hash).unwrap();

        assert_eq!(expected, actual);
    }
}
