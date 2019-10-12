use bitcoin::hashes::{sha256::Hash as Sha256, Hash, HashEngine, Hmac, HmacEngine};

const BLOCK_SIZE: usize = Sha256::LEN;

pub struct HKDFExtract;

pub struct HKDFExpand(Hmac<Sha256>);

impl HKDFExtract {
    pub fn extract(mut salt: &[u8], input: &[u8]) -> HKDFExpand {
        if salt.is_empty() {
            // TODO: this isn't needed because xoring with zero does nothing.
            salt = &[0u8; BLOCK_SIZE];
        }
        let mut hmac = HmacEngine::<Sha256>::new(salt);
        hmac.input(input);
        HKDFExpand(Hmac::from_engine(hmac))
    }
}

impl HKDFExpand {
    pub fn expand(self, info: &[u8], buf: &mut [u8]) {
        assert!(buf.len() <= BLOCK_SIZE * 255);
        let mut t: &[u8] = &[];
        let mut hmac_res;
        for (i, block) in buf.chunks_mut(BLOCK_SIZE).enumerate() {
            let mut hmac = HmacEngine::<Sha256>::new(&self.0[..]);
            hmac.input(&t[..]);
            hmac.input(info);
            hmac.input(&[1 + i as u8]);
            hmac_res = Hmac::from_engine(hmac);
            t = &hmac_res[..];
            block.copy_from_slice(&t[..block.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::Error;
    use bitcoin::util::misc::hex_bytes;

    struct TestVector {
        pub ikm: Vec<u8>,
        pub salt: Vec<u8>,
        pub info: Vec<u8>,
        pub prk: Vec<u8>,
        pub okm: Vec<u8>,
    }

    impl TestVector {
        pub fn new(ikm: &str, salt: &str, info: &str, prk: &str, okm: &str) -> Result<Self, Error> {
            Ok(TestVector {
                ikm: hex_bytes(ikm)?,
                salt: hex_bytes(salt)?,
                info: hex_bytes(info)?,
                prk: hex_bytes(prk)?,
                okm: hex_bytes(okm)?,
            })
        }
    }

    #[test]
    fn test_vectors_hkdf() {
        let tests = [
            TestVector::new("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                            "000102030405060708090a0b0c",
                            "f0f1f2f3f4f5f6f7f8f9",
                            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap(),
            TestVector::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
            ).unwrap(),
            TestVector::new("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                            "",
                            "",
                            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            ).unwrap(),
        ];

        for (i, test) in tests.iter().enumerate() {
            println!("{}", i);
            let prk = HKDFExtract::extract(&test.salt, &test.ikm);
            assert_eq!(&prk.0[..], &test.prk[..]);
            let mut okm = vec![0u8; test.okm.len()];
            prk.expand(&test.info, &mut okm);
            assert_eq!(okm, test.okm);
        }
    }
}
