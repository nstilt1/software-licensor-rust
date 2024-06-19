use base64::alphabet::Alphabet;
use http_private_key_manager::{
    private_key_generator::{
        ecdsa::SigningKey, hkdf::hmac::{digest::Output, Hmac}, typenum::Unsigned, EncodedId
    }, 
    utils::StringSanitization,
};
pub use http_private_key_manager::private_key_generator::{
    ecdsa::signature::DigestVerifier,
    hkdf::hmac::digest::{Digest, FixedOutput},
};
pub use p384::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey},
};
pub use p384::NistP384;
pub use p384;
pub use chacha20poly1305;
pub use http_private_key_manager;
use http_private_key_manager::prelude::*;
use proto::prost::Message;
pub use sha2;
use sha3::Sha3_512;
pub use aes_gcm::{Aes128Gcm, Aes256Gcm};
pub use chacha20poly1305::ChaCha20Poly1305;
use hex::decode;
#[cfg(feature = "local")]
use dotenv::dotenv;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::error::ApiError;

use std::sync::LazyLock;

/// A salt for the Stores table.
pub static STORE_DB_SALT: LazyLock<String> = LazyLock::new(|| {
    std::env::var("STORE_TABLE_SALT").expect("STORE_TABLE_SALT not set")
});
pub static LICENSE_DB_SALT: LazyLock<String> = LazyLock::new(|| {
    std::env::var("LICENSE_TABLE_SALT").expect("LICENSE_TABLE_SALT not set")
});

/// Constant for License Code Length. This depends on the `LicenseCode` `IdLen`,
/// as well as that the license code will be displayed in hexadecimal.
pub const LICENSE_CODE_LEN: usize = <LicenseCode as EncodedId>::IdLen::USIZE * 2;

pub mod license_types {
    pub const TRIAL: &str = "trial";
    pub const PERPETUAL: &str = "perpetual";
    pub const SUBSCRIPTION: &str = "subscription";
}

/// Hasher for the database. Sha3 is faster with `asm` on `aarch64`.
type DbHasher = sha3::Sha3_384;
/// Hashes data with a constant salt.
pub fn salty_hash(data: &[&[u8]], salt: &String) -> Output<DbHasher> {
    let mut digest = DbHasher::new();
    for d in data.iter() {
        digest.update(d);
    }
    digest.update(salt.as_bytes());
    digest.finalize()
}

#[cfg(feature = "dynamodb")]
use crate::{
    tables::stores::STORES_TABLE,
    dynamodb::maps_mk2::{AttributeValueHashMap, ItemIntegration},
};

#[cfg(feature = "dynamodb")]
pub trait ExtractPublicKey {
    /// Extracts a public key from a specific data structure.
    /// 
    /// Currently supports public key extraction from a `store_item`, as 
    /// well as a `RegisterStoreRequest`.
    fn extract_public_key(&self) -> Result<PublicKey, ApiError>;
}

#[cfg(feature = "dynamodb")]
impl ExtractPublicKey for AttributeValueHashMap {
    #[inline]
    fn extract_public_key(&self) -> Result<PublicKey, ApiError> {
        Ok(PublicKey::from_sec1_bytes(
            &self.get_item(STORES_TABLE.public_key)?.as_ref()
        )?)
    }
}

#[cfg(feature = "dynamodb")]
impl ExtractPublicKey for proto::protos::register_store_request::RegisterStoreRequest {
    #[inline]
    fn extract_public_key(&self) -> Result<PublicKey, ApiError> {
        Ok(PublicKey::from_sec1_bytes(
            &self.public_signing_key
        )?)
    }
}

/// Verifies a store's signature using their public key.
#[cfg(feature = "dynamodb")]
#[inline]
pub fn verify_signature<P, H>(public_key_container: &P, hasher: H, signature: &[u8]) -> Result<(), ApiError> 
where 
    P: ExtractPublicKey,
    H: Digest + FixedOutput
{
    let pubkey = public_key_container.extract_public_key()?;
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.try_into().unwrap())?;
    verifier.verify_digest(hasher, &signature)?;
    Ok(())
}

/// BigId shorthand type with 64 base64 chars.
type BigId<TimestampPolicy> = BinaryId<
    U48, // id length - 48 bytes or 64 base64 chars
    U8,  // MAC length - 8 bytes or 2^64 MACs and 2^(8x40) unique IDs (excluding prefixed ones)
    6,   // prefix length
    TimestampPolicy
>;

type MediumId<TimestampPolicy> = BinaryId<
    U24, // id length - 24 bytes or 32 base64 chars
    U8, // mac length - 8 bytes or 2^64 MACs
    6, // prefix length
    TimestampPolicy
>;

/// The ECDH Key ID format. Sometimes uses timestamps.
pub type EcdhKeyId = BigId<use_timestamps::Sometimes>;

/// The ECDSA Key ID format. Always uses timestamps.
pub type EcdsaKeyId = BigId<use_timestamps::Always>;

/// The binary format of a store ID.
pub type StoreId = BigId<use_timestamps::Never>;

/// The binary format of a Product ID, which doubles as an ECDSA key ID.
/// 
/// The private key will be used to sign responses, but the server's EcdsaKey ID
/// will also be used to double-sign the response because we want a rotating key's
/// signature.
pub type ProductId = MediumId<use_timestamps::Never>;

/// The binary format of a license code.
/// 
/// This LicenseCode type can be represented with 20 hexadigits, and it offers:
/// 
/// * a `2 in 16 million (16,777,216)` chance on average of a random ID passing the MAC check
/// * `1 trillion` unique IDs (per version, which changes yearly)
///   * `2^(80 IdLen bits - 14 VERSION_BITS - 24 MAC bits - 2 Constant bits) = 1,099,511,627,776`
pub type LicenseCode = BinaryId<
    U10, // id length for license codes is 10, or 20 hexadigits
    U3,  // MAC length offers a `2/16,777,216` average chance of beating the MAC verification
    0,  // no prefix

    // just because licenses can expire does not mean we want the license 
    // code to expire internally, because that would mean that we would have to
    // re-issue a user a new license code periodically. We will support 
    // re-generating license codes, but the license code itself will not expire 
    use_timestamps::Never,
>;

type Versioning = AnnualVersionConfig<
    14,            // 14 version bits
    8,             // 8 bits of precision loss result in +128-384 seconds above timestamps
    18             // 18 timestamp bits with 8 bits of precision loss is exactly enough to represent 2 years (including leap time)
>;

type KeyGen = KeyGenerator<
    Hmac<Sha3_512>, 
    Versioning, 
    ChaCha8Rng, 
    Sha3_512
>;

pub type EcdsaAlg = NistP384;
type EcdhAlg = NistP384;
type EcdhDigest = sha2::Sha384;
pub type EcdsaDigest = sha2::Sha384;

pub type KeyManager = HttpPrivateKeyManager<
    KeyGen, // key generator
    EcdhAlg, // ecdh algo
    EcdhDigest, 
    EcdsaAlg, 
    EcdsaDigest,
    StoreId, 
    EcdhKeyId,
    EcdsaKeyId, 
    ChaCha8Rng
>;

/// Initializes a Key manager. 
/// 
/// The key needs to be changed to something secure, and the initialization should probably be handled in conjunction with a `Box` or stack bleaching.
pub fn init_key_manager(kdf_key: Option<&[u8]>, alphabet: Option<&str>) -> KeyManager {
    #[cfg(feature = "local")]
    dotenv().ok();
    #[allow(unused_mut)]
    let mut key = decode(std::env::var("KEY_MANAGER_PRIVATE_KEY").expect("KEY_MANAGER_PRIVATE_KEY not set")).expect("KEY_MANAGER_PRIVATE_KEY should be hexadecimal");
    let result = KeyManager::from_key_generator(
        KeyGen::new(kdf_key.unwrap_or(&key), b"software licensor"), 
        Alphabet::new(alphabet.unwrap_or("qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM/_")).unwrap()
    );
    #[cfg(feature = "zeroize")]
    {
        key.zeroize();
    }
    result
}

pub trait DigitalLicensingThemedKeymanager {
    /// Generates a license code for a user
    /// 
    /// # Arguments
    /// 
    /// * `store_id` - The store's ID
    fn generate_license_code(&mut self, store_id: &Id<StoreId>) -> Result<Id<LicenseCode>, ApiError>;

    /// Generates a product ID with a desired prefix.
    /// 
    /// # Arguments
    /// 
    /// * `prefix` - A prefix for the plugin ID. This will be sanitized and trimmed
    /// * `store_id` - The store's ID
    /// 
    /// # Returns
    /// 
    /// This returns `(PluginId, Public Verifying key as sec1 bytes)`
    /// 
    /// ## Role in the License Activation Process
    /// 
    /// The public key needs to be sent to the store owner, to be inserted into their client-side code. The server will sign a plaintext key file with the key, and it will need to be verified as part of the license activation process.
    /// 
    /// Ideally, the key file will be encrypted when it is sent, but the client side code will store decrypted key file with the signature. For a signature with at least 128 bits of security, it should be difficult for the average end user to forge a valid signature for a modified key file.
    fn generate_product_id(&mut self, prefix: &str, store_id: &Id<StoreId>) -> Result<(Id<ProductId>, Box<[u8]>), ApiError>;
    
    /// Generates a store ID with a desired prefix. 
    /// 
    /// This method will sanitize and trim the prefix.
    /// 
    /// # Deprecated
    /// 
    /// Note that the store ID is generated automatically since we have set the `StoreId` as the `ClientId` type in the `HttpPrivateKeyManager`. Use `get_store_id()` to retrieve it, and use `regenerate_store_id()` to regenerate it in the event that there is a collision in the database.
    /// 
    /// # Arguments
    /// 
    /// * `prefix` - the desired prefix. This should be UTF-8 encoded
    #[deprecated]
    fn generate_store_id(&mut self, prefix: &str) -> Result<Id<StoreId>, ApiError>;

    /// Gets the Store ID from a request.
    /// 
    /// If this is a handshake, it will return a freshly generated ID, and if there is a collision in the database, call `regenerate_store_id()` to make a new one.
    fn get_store_id(&self) -> Result<Id<StoreId>, ApiError>;

    /// Regenerates the Store ID.
    /// 
    /// This can be useful if there is a collision in the database.
    fn regenerate_store_id(&mut self) -> Result<Id<StoreId>, ApiError>;

    /// Checks if a license code is likely to be authentic. Just because this check passes does not mean that the license code is in the database.
    /// 
    /// # Arguments
    /// 
    /// * `license_code` - the user-supplied license code in UTF-8 format. It will be sanitized.
    /// * `store_id` - the user-supplied store ID
    /// * `product_id` - the user-supplied Product ID.
    /// 
    /// # Notes
    /// 
    /// Some of the "user-supplied" data is actually going to be sent automatically by the client-side code, but it could be sent maliciously from a script, and as such, it is treated as "user-supplied" data.
    fn validate_license_code(&mut self, license_code: &str, store_id: &Id<StoreId>) -> Result<Id<LicenseCode>, ApiError>;

    /// Checks if a product ID is likely to be authentic. Just because this check passes does not mean that the product ID is in the database.
    /// 
    /// # Arguments
    /// 
    /// * `product_id` - the user-supplied Product ID.
    /// * `store_id` - the user-supplied store ID
    /// 
    /// # Notes
    /// 
    /// Some of the "user-supplied" data is actually going to be sent automatically by the client-side code, but it could be sent maliciously from a script, and as such, it is treated as "user-supplied" data.
    fn validate_product_id(&mut self, product_id: &str, store_id: &Id<StoreId>) -> Result<Id<ProductId>, ApiError>;

    /// Checks if a store ID is likely to be authentic. Just because this check passes does not mean that the store ID is in the database.
    /// 
    /// # Deprecated
    /// 
    /// This method is deprecated and only used for tests because the `ClientId` type in the `HttpPrivateKeyManager` is set to the `StoreId`, and the `decrypt_and_hash_request()` method will automatically validate the `ClientId`.
    /// 
    /// # Arguments
    /// 
    /// * `store_id` - the user-supplied store ID
    /// 
    /// # Notes
    /// 
    /// Some of the "user-supplied" data is actually going to be sent automatically by the client-side code, but it could be sent maliciously from a script, and as such, it is treated as "user-supplied" data.
    #[deprecated]
    fn validate_store_id(&mut self, store_id: &str) -> Result<Id<StoreId>, ApiError>;

    /// Attempts to sign a key file.
    /// 
    /// # Arguments
    /// 
    /// * `key_file` - the key file that needs to be signed
    /// * `product_id` - the product ID that the key file is for
    fn sign_key_file(&mut self, key_file: &[u8], product_id: &Id<ProductId>) -> Result<Vec<u8>, ApiError>;

    /// Gets the product's public key.
    fn get_product_public_key(&mut self, product_id: &Id<ProductId>, store_id: &Id<StoreId>) -> Vec<u8>;

    /// Encrypts and zeroizes a `StoreDbItem`
    fn encrypt_db_proto<M: Message>(&mut self, table_name: &str, related_id: &[u8], data: &M) -> Result<Vec<u8>, ApiError>;

    /// Decrypts a `StoreDbItem`
    fn decrypt_db_proto<M: Message + Default>(&mut self, table_name: &str, related_id: &[u8], data: &[u8]) -> Result<M, ApiError>;
}

/// Creates a license from raw binary in the database.
pub fn bytes_to_license(license_binary: &[u8]) -> String {
    encode_to_hex_with_dashes(license_binary, 5)
}

impl DigitalLicensingThemedKeymanager for KeyManager {
    #[inline]
    fn generate_license_code(&mut self, store_id: &Id<StoreId>) -> Result<Id<LicenseCode>, ApiError> {
        let associated_data = store_id.binary_id.as_ref();
        #[allow(unused_mut)]
        let mut id = self.key_generator.generate_keyless_id::<LicenseCode>(&[], b"license code", None, Some(&associated_data), &mut self.rng)?;

        let encoded_str = encode_to_hex_with_dashes(id.as_ref(), 5);
        let r = Ok(Id::new(&id, encoded_str, Some(associated_data)));

        #[cfg(feature = "zeroize")]
        id.as_mut().zeroize();
        r
    }

    #[inline]
    fn generate_product_id(&mut self, prefix: &str, store_id: &Id<StoreId>) -> Result<(Id<ProductId>, Box<[u8]>), ApiError> {
        let (mut id, key) = self.generate_ecdsa_key_and_id::<EcdsaAlg, ProductId>(prefix, None, Some(store_id.binary_id.as_ref()))?;
        id.encoded_id.insert(ProductId::MAX_PREFIX_LEN / 3 * 4, '-');
        Ok((id, key.verifying_key().to_sec1_bytes()))
    }

    #[inline]
    fn generate_store_id(&mut self, prefix: &str) -> Result<Id<StoreId>, ApiError> {
        let mut id = self.generate_keyless_id::<StoreId>(prefix, b"Store ID", None, None)?;
        id.encoded_id.insert(StoreId::MAX_PREFIX_LEN / 3 * 4, '-');
        Ok(id)
    }

    #[inline]
    fn get_store_id(&self) -> Result<Id<StoreId>, ApiError> {
        let mut id = self.get_client_id()?;
        id.encoded_id.insert(StoreId::MAX_PREFIX_LEN / 3 * 4, '-');
        Ok(id)
    }

    #[inline]
    fn regenerate_store_id(&mut self) -> Result<Id<StoreId>, ApiError> {
        self.regenerate_client_id()?;
        self.get_store_id()
    }

    #[inline]
    fn validate_license_code(&mut self, license_code: &str, store_id: &Id<StoreId>) -> Result<Id<LicenseCode>, ApiError> {
        let mut sanitized = license_code.sanitize_str("abcdefABCDEF1234567890");
        sanitized.truncate(LICENSE_CODE_LEN);
        let decoded = decode_hex::<LicenseCode>(&sanitized)?;

        let associated_data = store_id.binary_id.as_ref();

        let id = if let Ok(id) = self.key_generator.validate_keyless_id::<LicenseCode>(&decoded, b"license code", Some(&associated_data)) {
            id
        } else {
            return Err(ApiError::InvalidLicenseCode)
        };

        Ok(Id::new(&id, license_code.to_string(), Some(associated_data)))
    }

    #[inline]
    fn validate_product_id(&mut self, product_id: &str, store_id: &Id<StoreId>) -> Result<Id<ProductId>, ApiError> {
        let id = self.validate_ecdsa_key_id::<EcdsaAlg, ProductId>(product_id, Some(store_id.binary_id.as_ref()))?;
        Ok(id)
    }

    #[inline]
    fn validate_store_id(&mut self, store_id: &str) -> Result<Id<StoreId>, ApiError> {
        Ok(self.validate_keyless_id::<StoreId>(store_id, b"Store ID", None)?)
    }

    #[inline]
    fn sign_key_file(&mut self, key_file: &[u8], product_id: &Id<ProductId>) -> Result<Vec<u8>, ApiError> {
        Ok(self.sign_data_with_key_id::<EcdsaAlg, ProductId, EcdsaDigest>(key_file, product_id)?.to_vec())
    }

    #[inline]
    fn get_product_public_key(&mut self, product_id: &Id<ProductId>, store_id: &Id<StoreId>) -> Vec<u8> {
        let signing_key: SigningKey<EcdsaAlg> = self.key_generator.generate_ecdsa_key_from_id(
            &product_id.binary_id, 
            Some(store_id.binary_id.as_ref()),
        );

        signing_key.verifying_key().to_sec1_bytes().to_vec()
    }

    #[inline]
    fn encrypt_db_proto<M: Message>(&mut self, table_name: &str, related_id: &[u8], data: &M) -> Result<Vec<u8>, ApiError> {
        #[allow(unused_mut)]
        let mut encoded = data.encode_length_delimited_to_vec();

        let encrypted = self.encrypt_resource::<ChaCha20Poly1305>(encoded.as_slice(), table_name.as_bytes(), related_id, &[])?;
        
        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        Ok(encrypted)
    }

    #[inline]
    fn decrypt_db_proto<M: Message + Default>(&mut self, table_name: &str, related_id: &[u8], data: &[u8]) -> Result<M, ApiError> {
        #[allow(unused_mut)]
        let mut decrypted = self.decrypt_resource::<ChaCha20Poly1305>(data, table_name.as_bytes(), related_id, &[])?;

        let decoded = if let Ok(d) = M::decode_length_delimited(decrypted.as_slice()) {
            d
        } else {
            return Err(ApiError::InvalidDbSchema("Store DB's protobuf data didn't match the .proto file".into()))
        };

        #[cfg(feature = "zeroize")]
        decrypted.zeroize();

        Ok(decoded)
    }
}

/// Evenly inserts dashes into a hex string with 4 characters between each dash.
/// 
/// # Arguments
/// 
/// * `data` - the data to encode to hexadecimal; this must be at most 16 bytes
/// * `num_four_char_sections` - the amount of four-character sections; this must not exceed 8
#[inline]
fn encode_to_hex_with_dashes(data: &[u8], num_four_char_sections: usize) -> String {
    assert!(data.len() <= 16);
    assert!(num_four_char_sections <= 8);

    let mut arr = [0u8; 16];
    arr[0..data.len()].copy_from_slice(data);
    let mut formatted = vec!['-' as u8; (num_four_char_sections << 2) + num_four_char_sections - 1];
    let encoded = format!("{:0width$X}", u128::from_le_bytes(arr), width = (num_four_char_sections << 2));
    for i in 0..num_four_char_sections {
        let src_index = i << 2;
        let dest_index = src_index + i;
        formatted[dest_index..dest_index + 4].copy_from_slice(&encoded.as_bytes()[src_index..src_index + 4])
    }
    String::from_utf8(formatted).expect("This should be utf-8")
}

/// Decodes hex to binary.
fn decode_hex<Id: EncodedId>(str: &str) -> Result<Vec<u8>, ApiError> {
    let sanitized = str.sanitize_str("0123456789ABCDEFabcdef");
    if sanitized.len() != Id::IdLen::USIZE << 1 {
        return Err(ApiError::InvalidAuthentication)
    }
    assert!(Id::IdLen::USIZE <= 16);
    let u = u128::from_str_radix(&sanitized, 16).unwrap();
    let bytes = &u.to_le_bytes()[..Id::IdLen::USIZE];
    Ok(bytes.to_vec())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// If this test compiles, then the constant params we have chosen to configure the key_manager with are valid.
    #[test]
    fn test_compile() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("TEST Store").unwrap();
        let (plugin_id, _) = key_manager.generate_product_id("TEST plugin", &store_id).unwrap();
        let license_code = key_manager.generate_license_code(&store_id).unwrap();

        // to print the IDs in a test:
        // cargo test -- --nocapture
        println!("Store ID = {}", store_id.encoded_id);
        println!("Plugin ID = {}", plugin_id.encoded_id);
        println!("License Code = {}", license_code.encoded_id);
        assert!(true)
    }

    #[test]
    fn small_prefix_sizes() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("").unwrap();
        let (_plugin_id, _) = key_manager.generate_product_id("", &store_id).unwrap();
        let store_id = key_manager.generate_store_id("a").unwrap();
        let (_plugin_id, _) = key_manager.generate_product_id("a", &store_id).unwrap();

        // to print the IDs in a test:
        // cargo test -- --nocapture
        assert!(true)
    }

    #[test]
    fn validation() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("Please work, ty").unwrap();
        let (plugin_id, _) = key_manager.generate_product_id("pretty please", &store_id).unwrap();
        let license_code = key_manager.generate_license_code(&store_id).unwrap();

        // validation, in the order that it will need to be validated in the real code
        // the encoded_ids will be given to developers, and the server will receive them in http requests
        let verified_store_id = key_manager.validate_store_id(&store_id.encoded_id);
        assert_eq!(verified_store_id.is_ok(), true);

        let store_id = verified_store_id.unwrap();
        let verified_plugin_id = key_manager.validate_product_id(&plugin_id.encoded_id, &store_id);
        assert_eq!(verified_plugin_id.is_ok(), true);

        let _plugin_id = verified_plugin_id.unwrap();
        let verified_license = key_manager.validate_license_code(&license_code.encoded_id, &store_id);
        assert_eq!(verified_license.is_ok(), true);
    }

    #[test]
    fn print_table_ids() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("TEST Store").unwrap();
        let (plugin_id, _) = key_manager.generate_product_id("TEST plugin", &store_id).unwrap();
        let license_code = key_manager.generate_license_code(&store_id).unwrap();

        // to print the IDs in a test:
        // cargo test -- --nocapture
        println!("Store ID = {}", store_id.encoded_id);
        println!("Plugin ID = {}", plugin_id.encoded_id);
        println!("License Code = {}", license_code.encoded_id);
        assert!(true)
    }
}