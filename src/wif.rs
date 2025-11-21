use num_bigint::BigUint;
use sha2::{Digest, Sha256};

#[cfg(test)]
pub fn wif_to_private_key(wif: &str) -> [u8; 32] {
    let decoded = bs58::decode(wif).into_vec().unwrap();
    let mut k: [u8; 32] = [0; 32];
    k.copy_from_slice(&decoded[1..33]);
    k
}

pub fn private_key_to_wif(private_key: &BigUint, compressed: bool) -> String {
    // Step 1: Convert private key to 32-byte array
    let mut key_bytes = private_key.to_bytes_be();

    // Pad with leading zeros if necessary to make it exactly 32 bytes
    while key_bytes.len() < 32 {
        key_bytes.insert(0, 0);
    }

    // Step 2: Add version byte (0x80 for mainnet)
    let mut extended_key = vec![0x80];
    extended_key.extend_from_slice(&key_bytes);

    // Step 3: Add compression flag if compressed
    if compressed {
        extended_key.push(0x01);
    }

    // Step 4: Perform double SHA256 hash for checksum
    let first_hash = Sha256::digest(&extended_key);
    let second_hash = Sha256::digest(&first_hash);

    // Step 5: Append first 4 bytes as checksum to extended key
    extended_key.extend_from_slice(&second_hash[0..4]);

    bs58::encode(extended_key).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, BigUint, Sign};
    use num_traits::Num;
    use parameterized_macro::parameterized;

    #[parameterized(expected_key = {"1", "1", "2", "3","abcdef0", "abcdef0"}, wif = {
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", //uncompressed
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", //compressed
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreB1FQ8BZ",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kGg2VfFazGNW", //uncompressed
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7zBFbVooFaV5N", //compressed
    })]
    fn can_convert_wif_to_private_key(expected_key: &str, wif: &str) {
        let actual_key = wif_to_private_key(wif);
        assert_eq!(
            expected_key,
            BigInt::from_bytes_be(Sign::Plus, &actual_key).to_str_radix(16)
        );
    }

    #[parameterized(key = {"1", "1", "2", "3","abcdef0", "abcdef0", "c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"}, expected_wif = {
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", //uncompressed
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", //compressed
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreB1FQ8BZ",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kGg2VfFazGNW", //uncompressed
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7zBFbVooFaV5N", //compressed
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    },
    compressed = {false, true, false, false, false, true, false})]
    fn can_convert_private_key_to_wif(key: &str, expected_wif: &str, compressed: bool) {
        let private_key = BigUint::from_str_radix(key, 16).unwrap();
        let wif = private_key_to_wif(&private_key, compressed);
        assert_eq!(expected_wif, wif);

        let private_key = wif_to_private_key(&wif);
        assert_eq!(
            key,
            BigInt::from_bytes_be(Sign::Plus, &private_key).to_str_radix(16)
        );
    }
}
