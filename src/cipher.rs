#![allow(dead_code)]
use crate::raw_bytes::*;
use itertools::Itertools;
use openssl::symm::{Cipher, Crypter, Mode};
use std::collections::HashSet;

pub fn single_key_xor(rb: &RawBytes, byte: u8) -> RawBytes {
    let data = rb.bytes.iter().map(|b| b ^ byte).collect();

    RawBytes { bytes: data }
}

pub fn repeating_key_xor(rb: &RawBytes, key: &RawBytes) -> RawBytes {
    let key = key.bytes.iter().cycle();
    let data = rb.bytes.iter().zip(key).map(|(b, k)| b ^ k).collect();

    RawBytes { bytes: data }
}

pub fn all_xors(rb: &RawBytes) -> Vec<(u8, RawBytes)> {
    let rb_cp = rb.clone();
    (0..=255)
        .map(move |c: u8| (c, single_key_xor(&rb_cp, c)))
        .collect()
}

pub fn score_for_english(rb: &RawBytes) -> i32 {
    let mut score = 0;

    for b in &rb.bytes {
        let ch = *b as char;

        if ch == 'e' {
            score += 10;
        } else if ch == 't' {
            score += 9;
        } else if ch == 'o' {
            score += 8;
        } else if ch == 'i' {
            score += 7;
        } else if ch == 'n' {
            score += 6;
        }
        if ch.is_ascii_whitespace() {
            score += 5;
        } else if ch.is_ascii_lowercase() {
            score += 4;
        } else if ch.is_ascii_uppercase() {
            score += 2;
        } else if ch.is_numeric() {
            score += 1;
        } else {
            score -= 2;
        }
    }
    score
}

pub fn sort_by_english_score(mut rbs: Vec<RawBytes>) -> Vec<RawBytes> {
    rbs.sort_by_key(|x| score_for_english(&x));
    rbs
}

pub fn single_char_xor_decrypt_impl(rb: &RawBytes) -> (u8, RawBytes) {
    let mut xors = all_xors(&rb);
    xors.sort_by_key(|x| score_for_english(&x.1));

    let b = xors.last().unwrap();
    (
        b.0,
        RawBytes {
            bytes: b.1.bytes.clone(),
        },
    )
}

pub fn single_char_xor_decrypt(rb: &RawBytes) -> RawBytes {
    let b = single_char_xor_decrypt_impl(rb);
    b.1.clone()
}

pub fn repeating_key_find_best_keysize(rb: &RawBytes) -> Vec<(usize, f64)> {
    let mut ans = Vec::new();
    for i in 2..40 {
        let it = rb.bytes.iter().chunks(i);
        let mut it = it.into_iter();
        let b1 = it.next().unwrap();
        let b2 = it.next().unwrap();
        let b3 = it.next().unwrap();
        let b4 = it.next().unwrap();

        let mut hamming_dist: f64 = 0.0;
        for (c1, c2, c3, c4) in itertools::multizip((b1, b2, b3, b4)) {
            let a1 = RawBytes::hamming_distance_byte(c1, c2);
            let a2 = RawBytes::hamming_distance_byte(c1, c3);
            let a3 = RawBytes::hamming_distance_byte(c1, c4);
            let a4 = RawBytes::hamming_distance_byte(c2, c3);
            let a5 = RawBytes::hamming_distance_byte(c2, c4);
            let a6 = RawBytes::hamming_distance_byte(c3, c4);
            hamming_dist += (a1 + a2 + a3 + a4 + a5 + a6) as f64 / 6.0;
        }
        ans.push((i, hamming_dist as f64 / i as f64));
    }
    ans.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    ans
}

pub fn repeating_key_xor_decrypt(rb: &RawBytes) -> Vec<RawBytes> {
    let key_sizes = repeating_key_find_best_keysize(rb);

    let mut ans = Vec::new();

    let experiments = 1;
    for (k, _) in key_sizes.iter().take(experiments) {
        let mut key = Vec::new();
        //dbg!(*k);
        for i in 0..*k {
            let bytes: Vec<u8> = rb.bytes.iter().skip(i).step_by(*k).map(|x| *x).collect();

            let rb = RawBytes { bytes };

            let b = single_char_xor_decrypt_impl(&rb);
            key.push(b.0);
        }
        let candidate = repeating_key_xor(rb, &RawBytes { bytes: key });
        ans.push(candidate);
    }
    ans
}

pub fn aes_128_ecb_decrypt_with_key(rb: &RawBytes, key: &RawBytes) -> anyhow::Result<RawBytes> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, &key.bytes, None)?;
    decrypter.pad(false);
    let mut decrypted = vec![0u8; 1024 * 3];
    let mut bytes = decrypter.update(&rb.bytes, decrypted.as_mut_slice())?;
    bytes += decrypter.finalize(decrypted.as_mut_slice())?;

    Ok(RawBytes {
        bytes: decrypted[..bytes].into(),
    })
}

pub fn aes_128_ecb_detect(rbs: &Vec<RawBytes>) -> Vec<(RawBytes, usize, i32)> {
    let block_size: usize = 16;

    let similar_score = |rb: &RawBytes| {
        let total_blocks = rb.bytes.len() / block_size;

        let mut different_blocks: HashSet<Vec<u8>> = HashSet::new();
        for i in 0..total_blocks {
            let x = rb
                .bytes
                .iter()
                .skip(block_size * i)
                .take(block_size)
                .map(|x| *x)
                .collect();
            different_blocks.insert(x);
        }

        total_blocks - different_blocks.len()
    };

    let mut ans: Vec<(RawBytes, usize, i32)> = rbs
        .iter()
        .enumerate()
        .map(|(id, rb)| (rb.clone(), id, similar_score(rb) as i32))
        .collect();

    ans.sort_by_key(|x| x.2);
    ans.reverse();
    ans
}

pub fn add_pkcs7_padding<'a>(rbs: &'a RawBytes, block_len: usize) -> impl Iterator<Item = u8> + 'a {
    let len = rbs.bytes.len();

    let pad_len = block_len - len % block_len;

    rbs.bytes
        .iter()
        .map(|x| *x)
        .chain(std::iter::repeat(pad_len as u8).take(pad_len).into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_xor_decrypt() {
        let rb = RawBytes::from_hex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        );

        assert_eq!(
            "Cooking MC's like a pound of bacon",
            single_char_xor_decrypt(&rb).to_str()
        );
    }

    #[test]
    fn test_decrypt_single_file() {
        let data = std::fs::read_to_string("inputs/set4.txt").unwrap();
        let decryted_strings: Vec<RawBytes> = data
            .lines()
            .map(|s| RawBytes::from_hex(s))
            .map(|b| single_char_xor_decrypt(&b))
            //.inspect(|s| println!("{:?}", s))
            .collect();
        let decryted_strings = sort_by_english_score(decryted_strings);

        let best_str: Vec<String> = decryted_strings
            .iter()
            .rev()
            .take(10)
            .map(|s| s.to_str())
            .collect();
        //.for_each(|s| println!("{}", s));
        assert_eq!(best_str[0], "Now that the party is jumping\n");
    }

    #[test]
    fn test_repeating_key_xor() {
        let data = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let data = RawBytes::from_str(data);
        let key = RawBytes::from_str("ICE");

        let ans = repeating_key_xor(&data, &key);

        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(expected, ans.to_hex());
    }

    #[test]
    fn test_repeating_key_find_best_keysize() {
        let data = std::fs::read_to_string("./inputs/set6.txt").unwrap();

        let data: String = data.lines().join("");

        let rb = RawBytes::from_base64(&data);

        let x = repeating_key_find_best_keysize(&rb);

        //dbg!(rb.to_str());
        dbg!(&x);
        assert_eq!(29, x[0].0);

        let ans = repeating_key_xor_decrypt(&rb);

        let ans: Vec<String> = ans.iter().map(|x| x.to_str()).collect();
        dbg!(&ans);
        assert_eq!(
            "I\'m back and I\'m ringin\' the bell ",
            ans[0].lines().next().unwrap()
        );
    }

    #[test]
    fn test_aes_128_ecb() {
        let key = RawBytes::from_str("YELLOW SUBMARINE");
        let data = std::fs::read_to_string("./inputs/set7.txt").unwrap();

        let data: String = data.lines().join("");

        let rb = RawBytes::from_base64(&data);

        let ans = aes_128_ecb_decrypt_with_key(&rb, &key).unwrap();

        println!("{:?}", rb.to_hex());
        println!("{}", ans.to_str());

        assert_eq!(
            "I'm back and I'm ringin' the bell ",
            ans.to_str().lines().nth(0).unwrap()
        );
    }

    #[test]
    fn test_detect_aes_128_ecb() {
        let data = std::fs::read_to_string("./inputs/set8.txt").unwrap();

        let data: Vec<RawBytes> = data.lines().map(|s| RawBytes::from_base64(s)).collect();

        let ans = aes_128_ecb_detect(&data);

        assert_eq!(ans[0].1, 132);
        assert_eq!(ans[0].2, 3);
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = RawBytes::from_str("YELLOW SUBMARINE");

        let ans: Vec<u8> = add_pkcs7_padding(&data, 20).collect();

        assert_eq!(ans[..data.bytes.len()], data.bytes[..]);
        assert_eq!(ans[data.bytes.len()..], vec![0x04, 0x04, 0x04, 0x04][..]);

        let data = RawBytes::from_str("ABC");

        let ans: Vec<u8> = add_pkcs7_padding(&data, 3).collect();

        assert_eq!(ans[..data.bytes.len()], data.bytes[..]);
        assert_eq!(ans[data.bytes.len()..], vec![0x03, 0x03, 0x03][..]);
    }
}
