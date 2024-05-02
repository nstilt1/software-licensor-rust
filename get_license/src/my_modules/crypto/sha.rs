use openssl::sha::Sha256;

/**
 * Salts and hashes an email address
 */
impl Hashing for &str {
    fn to_hash(&self) -> Vec<u8> {
        
        let mut hasher = Sha256::new();

        hasher.update(self.as_bytes());

        return hasher.finish().to_vec();
        
    }
}
impl Hashing for String {
    fn to_hash(&self) -> Vec<u8> {
        return self.as_str().to_hash();
    }
}
/**
 * Hashes a string
 */

pub trait Hashing {
    fn to_hash(&self) -> Vec<u8>;
}