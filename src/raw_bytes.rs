#![allow(dead_code)]
use itertools::Itertools;
use std::ops::BitXor;

#[derive(Debug)]
pub struct RawBytes {
    pub bytes: Vec<u8>,
}

impl RawBytes {
    pub fn new() -> Self {
        RawBytes { bytes: Vec::new() }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            bytes: s.chars().map(|c| c as u8).collect(),
        }
    }

    pub fn from_hex(str: &str) -> Self {
        let x = str.chars().step_by(2);
        let y = str.chars().skip(1).step_by(2);

        let to_num = |a| -> u8 {
            if a >= '0' && a <= '9' {
                a as u8 - '0' as u8
            } else if a >= 'a' && a <= 'z' {
                10 + a as u8 - 'a' as u8
            } else {
                10 + a as u8 - 'A' as u8
            }
        };
        let bytes = itertools::zip(x, y)
            .map(|(a, b)| 16 * to_num(a) + to_num(b))
            .collect();
        Self { bytes }
    }

    pub fn to_str(&self) -> String {
        let s = self.bytes.iter().map(|c| *c as char).join("");
        s
    }

    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|c: &u8| format!("{:02x}", c))
            .join("")
    }

    pub fn from_base64(str: &str) -> Self {
        let byte_to_bits = |byte| (0..6).rev().map(move |x: u8| -> u8 { (byte >> x) & 0x1 });

        let num_equals = str.chars().rev().take_while(|x| *x == '=').count();

        let mut bits = str.chars().count() - num_equals;
        bits = bits * 6 - (num_equals * 2);

        let bytes = str
            .chars()
            .map(|c| -> u8 {
                if c >= 'A' && c <= 'Z' {
                    c as u8 - 'A' as u8
                } else if c >= 'a' && c <= 'z' {
                    c as u8 - 'a' as u8 + 26
                } else if c >= '0' && c <= '9' {
                    c as u8 - '0' as u8 + 52
                } else if c == '+' {
                    62
                } else if c == '/' {
                    63
                } else {
                    65
                }
            })
            .filter(|c| c < &65)
            .flat_map(byte_to_bits)
            .take(bits)
            .chunks(8)
            .into_iter()
            .map(|c| {
                let mut ans: u8 = 0;
                let mut multiplier: u8 = 128;

                for x in c {
                    ans += x * multiplier;
                    multiplier /= 2;
                }
                ans
            })
            .collect();

        RawBytes { bytes }
    }

    pub fn to_base64(&self) -> String {
        let byte_to_bits = |byte| (0..8).rev().map(move |x: u8| -> u8 { (byte >> x) & 0x1 });

        let mut padding_len = self.bytes.len() % 3;
        if padding_len > 0 {
            padding_len = 3 - padding_len;
        }

        let padding = std::iter::repeat('=').take(padding_len);

        let bits = self
            .bytes
            .iter()
            .flat_map(|n| byte_to_bits(n))
            .chunks(6)
            .into_iter()
            .map(|c| {
                let mut ans: u8 = 0;
                let mut multiplier: u8 = 32;

                for x in c {
                    ans += x * multiplier;
                    multiplier /= 2;
                }

                let base64_char = if ans < 26 {
                    (ans + 'A' as u8) as char
                } else if ans < 52 {
                    (ans - 26 + 'a' as u8) as char
                } else if ans < 62 {
                    (ans - 52 + '0' as u8) as char
                } else if ans < 63 {
                    '+'
                } else {
                    '/'
                };

                base64_char
            })
            .chain(padding)
            .collect();

        bits
    }

    pub fn hamming_distance_byte(l: &u8, h: &u8) -> i32 {
        let mut ans: i32 = 0;
        let x = l ^ h;

        for i in 0..8 {
            ans += ((x >> i) & 0x1) as i32;
        }
        ans
    }

    pub fn hamming_distance(&self, rhs: &RawBytes) -> anyhow::Result<i32> {
        if self.bytes.len() != rhs.bytes.len() {
            anyhow::bail!("lhs and rhs need to be of same len");
        }

        let dist = self
            .bytes
            .iter()
            .zip(rhs.bytes.iter())
            .map(|(l, h)| Self::hamming_distance_byte(l, h))
            .sum();
        Ok(dist)
    }
}

impl BitXor for RawBytes {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let bytes = self
            .bytes
            .iter()
            .zip(rhs.bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        Self::Output { bytes }
    }
}

impl PartialEq for RawBytes {
    fn eq(&self, other: &RawBytes) -> bool {
        return self.bytes == other.bytes;
    }
}

impl Clone for RawBytes {
    fn clone(&self) -> Self {
        RawBytes {
            bytes: self.bytes.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tohex_simpl3() {
        let mut rb = RawBytes::new();
        rb.bytes.push(2);
        assert!(rb.to_hex() == "02");

        rb.bytes.push(15);
        println!("{}", rb.to_hex());
        assert!(rb.to_hex() == "020f");
    }

    fn test_fromhex_simple() {
        let rb = RawBytes::from_hex("02");

        let expected = vec![2];
        assert!(rb.bytes == expected);

        let rb = RawBytes::from_hex("020f");

        let expected = vec![2, 15];
        assert!(rb.bytes == expected);
    }

    #[test]
    fn test_from_hex2() {
        let rb = RawBytes::from_hex("0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032");
        println!("{:?}", rb);
        //assert_eq!(0, 1);
    }

    #[test]
    fn test_tohex() {
        let mut rb = RawBytes::new();

        for i in 0..=255 {
            rb.bytes.push(i);
        }

        let mut expected = String::new();
        for i in 0..=255 {
            expected += &format!("{:02x}", i);
        }

        assert!(rb.to_hex() == expected);
    }

    #[test]
    fn test_round_trip_hex() {
        let mut rb = RawBytes::new();

        for i in 0..=255 {
            rb.bytes.push(i);
        }

        let rb2 = RawBytes::from_hex(&rb.to_hex());

        assert!(rb.bytes == rb2.bytes);
    }

    #[test]
    fn test_base64_simple() {
        let tests = vec![
            ("Man", "TWFu"),
            ("Ma", "TWE="),
            ("M", "TQ=="),
            ("pleasure.", "cGxlYXN1cmUu"),
            ("leasure.", "bGVhc3VyZS4="),
            ("easure.", "ZWFzdXJlLg=="),
            ("asure.", "YXN1cmUu"),
            ("sure.", "c3VyZS4="),
            //("xxxx", "CRIwqt4+"), //091230aade3e
        ];

        for t in tests.clone() {
            let rb = RawBytes::from_str(t.0);
            assert_eq!(rb.to_base64(), t.1);
        }

        for t in tests {
            let rb = RawBytes::from_base64(t.1);
            dbg!(t);
            dbg!(&rb.to_hex());
            assert_eq!(rb.to_str(), t.0);
        }

        // long string test:
        let s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let ans = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let rb = RawBytes::from_hex(s);
        assert_eq!(rb.to_base64(), ans);
        let rb = RawBytes::from_base64(ans);
        assert_eq!(rb.to_hex(), s);
    }

    #[test]
    fn test_xor() {
        let b1 = RawBytes::from_hex("1c0111001f010100061a024b53535009181c");
        let b2 = RawBytes::from_hex("686974207468652062756c6c277320657965");

        let ans = RawBytes::from_hex("746865206b696420646f6e277420706c6179");

        assert_eq!(b1 ^ b2, ans);
    }

    #[test]
    fn test_hamming_distance() {
        let b1 = RawBytes::from_str("this is a test");
        let b2 = RawBytes::from_str("wokka wokka!!!");

        let ans = b1.hamming_distance(&b2);
        let ans = ans.unwrap();
        assert_eq!(37, ans);
    }
}
