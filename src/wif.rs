#[cfg(test)]
pub fn wif_to_private_key(wif: &str) -> [u8; 32] {
    let decoded = bs58::decode(wif).into_vec().unwrap();
    let mut k: [u8; 32] = [0; 32];
    k.copy_from_slice(&decoded[1..33]);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, Sign};
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
}
