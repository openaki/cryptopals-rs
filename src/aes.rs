#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AesByte(u8);

impl AesByte {
    fn xtime(n: u8) -> u8 {
        let overflow = n & 0x80;
        let mut ans = n << 1;

        if overflow != 0 {
            ans = ans ^ 0x1b;
        }

        ans
    }
}

impl std::ops::Add for AesByte {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        AesByte(self.0 ^ rhs.0)
    }
}

impl std::ops::Mul for AesByte {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut m = rhs.0;
        let mut ans = 0;
        let mut multiplier = self.0;

        if m & 0x1 == 0x1 {
            ans = ans ^ multiplier;
        }

        m = m >> 1;
        while m > 0x0 {
            multiplier = AesByte::xtime(multiplier);

            if m & 0x1 == 0x1 {
                ans = ans ^ multiplier;
            }

            m = m >> 1;
        }

        AesByte(ans)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AesWord(AesByte, AesByte, AesByte, AesByte);

impl AesWord {
    fn from_bytes(a1: u8, a2: u8, a3: u8, a4: u8) -> Self {
        AesWord(AesByte(a1), AesByte(a2), AesByte(a3), AesByte(a4))
    }

    fn rotate_rigt(n: Self) -> Self {
        let AesWord(a, b, c, d) = n;
        AesWord(d, a, b, c)
    }

    fn get_mutiplier(n: Self) -> (Self, Self, Self, Self) {
        let AesWord(a0, a1, a2, a3) = n;

        let f = AesWord;

        (
            f(a0, a3, a2, a1),
            f(a1, a0, a3, a2),
            f(a2, a1, a0, a3),
            f(a3, a2, a1, a0),
        )
    }

    fn dot(w1: Self, w2: Self) -> AesByte {
        let AesWord(a0, a1, a2, a3) = w1;
        let AesWord(b0, b1, b2, b3) = w2;

        (a0 * b0) + (a1 * b1) + (a2 * b2) + (a3 * b3)
    }
}

impl std::ops::Add for AesWord {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        AesWord(
            self.0 + rhs.0,
            self.1 + rhs.1,
            self.2 + rhs.2,
            self.3 + rhs.3,
        )
    }
}

impl std::ops::Mul for AesWord {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let (m1, m2, m3, m4) = AesWord::get_mutiplier(self);

        //dbg!(m1, m2, m3, m4);

        AesWord(
            AesWord::dot(m1, rhs),
            AesWord::dot(m2, rhs),
            AesWord::dot(m3, rhs),
            AesWord::dot(m4, rhs),
        )
    }
}

struct AesUtil {}

impl AesUtil {}

struct AesEncrypt {
    num_words: u8,
    block_size_bytes: u8,
    num_rounds: u8,
}

impl AesEncrypt {
    fn new() -> Self {
        let num_words = 4;
        let block_size_bytes = 4;
        let num_rounds = 10;

        Self {
            num_words,
            block_size_bytes,
            num_rounds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_aes_byte() {
        assert_eq!(AesByte(0xd4), AesByte(0x57) + AesByte(0x83))
    }

    #[test]
    fn test_xtime_aes_byte() {
        assert_eq!((0xae), AesByte::xtime(0x57));
        assert_eq!((0x47), AesByte::xtime(0xae));
        assert_eq!((0x8e), AesByte::xtime(0x47));
        assert_eq!((0x07), AesByte::xtime(0x8e));
    }

    #[test]
    fn test_mul_aes_byte() {
        assert_eq!(AesByte(0xfe), AesByte(0x57) * AesByte(0x13))
    }

    #[test]
    fn test_mul_aes_word() {
        let c = AesWord::from_bytes;
        assert_eq!(
            c(0x02, 0x03, 0x04, 0x01),
            c(0x01, 0x02, 0x03, 0x04) * c(0x00, 0x00, 0x00, 0x01)
        );

        assert_eq!(
            c(0x01, 0x00, 0x00, 0x00),
            c(0x02, 0x01, 0x01, 0x03) * c(0x0e, 0x09, 0x0d, 0x0b)
        )
    }
}
