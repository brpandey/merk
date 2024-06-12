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

    pub fn new_shared_(hash_key: String, bytes: Vec<u8>) -> SharedHashPair {
        Rc::new(RefCell::new(HashPair::new(hash_key, bytes)))
    }
}

const HEX_PREFIX: &str = "0x";

// Unit struct to wrap hex encode and decode
pub struct Hex;

impl Hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        hex::encode(data)
    }

    pub fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, MerkError> {
        let bytes = hex::decode(data)?;
        Ok(bytes)
    }

    pub fn trim_prefix(text: &str) -> &str {
        text.trim_start_matches(HEX_PREFIX)
    }
}

// Unit struct HashConcat or HashCat for brevity
// Handles concatenating two byte slices before hashing
pub struct HashCat;

impl HashCat {
    // Hash Helper method
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

// Simple aggregate error type

#[derive(Error, Debug)]
pub enum MerkError {
    #[error("Unable to decode hex string into bytes vector -- {0}")]
    Hex(#[from] hex::FromHexError),
}
