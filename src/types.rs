use std::{cell::RefCell, rc::Rc};
use thiserror::Error;

pub type SharedHashPair = Rc<RefCell<HashPair>>;

#[derive(Debug)]
pub struct HashPair {
    pub hash_key: String,
    pub bytes: Vec<u8>,
}

impl HashPair {
    pub fn new(hash_key: String, bytes: Vec<u8>) -> Self {
        Self { hash_key, bytes }
    }

    pub fn new_shared_key(hash_key: String) -> Result<SharedHashPair, MerkError> {
        let bytes: Vec<u8> = Hex::decode(&hash_key)?;
        Ok(Self::new_shared(hash_key, bytes))
    }

    pub fn new_shared(hash_key: String, bytes: Vec<u8>) -> SharedHashPair {
        Rc::new(RefCell::new(HashPair::new(hash_key, bytes)))
    }
}

const HEX_PREFIX: &str = "0x";
const HEX_BASE: u32 = 16;

// Unit struct to wrap hex encode and decode
pub struct Hex;

impl Hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        hex::encode(data)
    }

    pub fn decode(value: &str) -> Result<Vec<u8>, MerkError> {
        let data = Hex::trim_prefix(value);
        let bytes = hex::decode(data)?;
        Ok(bytes)
    }

    pub fn trim_prefix(text: &str) -> &str {
        text.trim_start_matches(HEX_PREFIX)
    }

    // Given a value in hex string form, give ability to multiply it by scaling factor
    pub fn scale(scale: usize, value: &str) -> String {
        use num_bigint::BigInt;
        use num_traits::FromPrimitive;

        let v = Self::trim_prefix(value);

        if scale == 0 {
            return "0".repeat(v.len());
        }

        let big_value_int = BigInt::parse_bytes(v.as_bytes(), HEX_BASE).unwrap();
        let scaled_value = &big_value_int * BigInt::from_usize(scale).unwrap();

        scaled_value.to_str_radix(HEX_BASE)
    }
}

// Unit struct HashConcat or HashCat for brevity
// Handles concatenating two byte slices before hashing
pub struct HashCat;

impl HashCat {
    // Hash Helper methods
    pub fn concat_l(l: &str, r_bytes: &[u8]) -> Result<Vec<u8>, MerkError> {
        let l2 = Hex::trim_prefix(l);
        let l_bytes: Vec<u8> = Hex::decode(l2)?;

        Ok(Self::concat(&l_bytes, r_bytes))
    }

    pub fn concat_r(l_bytes: &[u8], r: &str) -> Result<Vec<u8>, MerkError> {
        let r2 = Hex::trim_prefix(r);
        let r_bytes: Vec<u8> = Hex::decode(r2)?;

        Ok(Self::concat(l_bytes, &r_bytes))
    }

    pub fn concat(l: &[u8], r: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};

        let concat = l
            .iter()
            .cloned()
            .chain(r.iter().cloned())
            .collect::<Vec<u8>>();

        let mut hasher = Sha3_256::new();
        hasher.update(concat); // input msg to be hashed
        hasher.finalize().to_vec() // hash operation
    }
}

// Simple aggregate error type to give calling code options

#[derive(Error, Debug, PartialEq)]
pub enum MerkError {
    #[error("Unable to decode hex string into bytes vector -- {0}")]
    Hex(#[from] hex::FromHexError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn hex_encode_decode_test() {
        use hex::FromHexError::OddLength;
        let error = MerkError::Hex(OddLength);

        // normal decode and encode
        assert_eq!(vec![171], Hex::decode("0xab").unwrap());
        assert_eq!(Hex::encode(vec![171]), "ab");

        // erroneous decode
        assert_eq!(Hex::decode("0xabc").unwrap_err(), error);
        assert_eq!(
            "Unable to decode hex string into bytes vector -- Odd number of digits",
            error.to_string()
        )
    }

    #[test]
    pub fn hash_single_concat_test() {
        let bytes = [171]; // str is 0xab e.g 10*16 + 11

        // Same value, concatenated
        let out = HashCat::concat(&bytes, &bytes);
        assert_eq!(
            Hex::encode(out),
            "5fdf86416e09b2b1c0b91afe771d4e6ada2b0daed0066f8aed911109e33f3e34"
        );

        // Different values
        let left =
            Hex::decode("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let right =
            Hex::decode("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let out = HashCat::concat(&left, &right);
        assert_eq!(
            Hex::encode(&out),
            "35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10"
        );

        // Again different values
        let left =
            Hex::decode("0x2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        let right =
            Hex::decode("0x3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();

        let out = HashCat::concat(&left, &right);
        assert_eq!(
            Hex::encode(out),
            "777d6e92478a47e81651fcd03f9f3aec04893589a865a171cb17127fdee83f64"
        );
    }

    #[test]
    pub fn hash_multiple_concat_test() {
        let depth = 20;
        let mut bytes =
            Hex::decode("0xabababababababababababababababababababababababababababababababab")
                .unwrap();
        let final_hash = "d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930";

        let level_bytes = [
            "699fc94ff1ec83f1abf531030e324003e7758298281645245f7c698425a5e0e7",
            "a2422433244a1da24b3c4db126dcc593666f98365403e6aaf07fae011c824f09",
            "ec46a8dbc7fb0da5753b11f3ff04ee6b7a2a979b168025d40394a0ff4cf2df59",
            "34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604",
            "b8b1810f54c4048913090d78983712bd54cd4bae4e236be1f294122388abef6b",
            "4a011043594c8c029ec6141932c555b99c464ab75734027aeb968ed87fd5275c",
            "90029acbe3254c63bc9dd4a8f1e4b8e27b4445bb5e5a5897af9251ec744f6f68",
            "1489ad5e85ce2b6cbccfd2f25f8d63d115ff80199afbc4ec4f6fc2484bf8d690",
            "c795494aa662dd012c5de6c52f0ab28ee9135fe846074d62bb7807cf98742fd9",
            "0684c3868080b6ec1e59f146537540b3d630d6134eb3b518ce5344b8760a0cb2",
            "700516179f04e9e01ebdbe2987e6aeb88ad46edf5eea903076ef39327ba5ba8b",
            "d5adfaba9b3c5018f7d23cd40aec48be24ec8ea7e1f861033490ee35de54716e",
            "d7d9ecf26ace864c9c0555464d32d51e2768d34e4c7a635463052a05d91e6720",
            "44ad1490179db284f6fa21d8effbd1ba6a3028042b96be9b249f538de3f57a85",
            "0b792ae9ba3ff7c8fb8c9e4763269193fc18841d2a668c4033ec2d8ccc6d7f58",
            "7dc85b760de6c2191d52216d9ddcfdd116a456d80bc3a627783b4218b4c57ea7",
            "ea93465267c9baf2feec9de4f15555ac2504eed493900ac033bbd0a8bb34ca63",
            "f460eaf964fa3cd41296e60efdbf6dd7df549c780c3fb9432e1784a89df84302",
            final_hash,
        ];

        // simulate the hash concat over a tree of depth
        for i in 0..depth - 1 {
            bytes = HashCat::concat(&bytes, &bytes);
            assert_eq!(Hex::encode(&bytes), level_bytes[i]);
        }
    }
}
