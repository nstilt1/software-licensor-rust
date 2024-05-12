use base64::alphabet::Alphabet;
use http_private_key_manager::{
    private_key_generator::{
        ecdsa::SigningKey, 
        hkdf::hmac::Hmac,
        hkdf::hmac::digest::{OutputSizeUser, Output}, 
        typenum::Unsigned, 
        EncodedId
    }, 
    utils::StringSanitization, 
    HttpPrivateKeyManager
};
pub use http_private_key_manager::private_key_generator::{
    ecdsa::signature::DigestVerifier,
    hkdf::hmac::digest::{Digest, FixedOutput}
};
pub use p384::{
    PublicKey,
    ecdsa::{DerSignature, VerifyingKey},
};
use p384::NistP384;
pub use http_private_key_manager;
use http_private_key_manager::prelude::*;
use proto::{prost::Message, protos::store_db_item::StoreDbItem};
use rand_chacha::ChaCha8Rng;
pub use sha2;
use sha3::{Sha3_384, Sha3_512};
pub use aes_gcm::{Aes128Gcm, Aes256Gcm};
pub use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
pub use chacha20poly1305::ChaCha20Poly1305;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::{error::ApiError, tables::stores::STORES_TABLE};

const DB_SALT: &[u8] = b"use a different salt than this for your own database";

/// Hashes data with a constant salt.
pub fn salty_hash<D: Digest + OutputSizeUser>(data: &[u8]) -> Output<D> {
    let mut digest = D::new();
    digest.update(data);
    digest.update(DB_SALT);
    digest.finalize()
}

/// BigId shorthand type with 64 base64 chars.
type BigId<TimestampPolicy> = BinaryId<
    U48, // id length - 48 bytes or 64 base64 chars
    U8,  // MAC length - 8 bytes or 2^64 MACs and 2^(8x40) unique IDs (excluding prefixed ones)
    6,   // prefix length
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
pub type ProductId = BigId<use_timestamps::Never>;

/// The binary format of a license code.
/// 
/// This LicenseCode type can be represented with 20 hexadigits, and it offers:
/// 
/// * a `2 in 16 million (16,777,216)` chance on average of a random ID passing the MAC check
/// * `1 trillion` unique IDs
///   * `2^(80 IdLen bits - 14 VERSION_BITS - 24 MAC bits - 2 Constant bits = 1,099,511,627,776`
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
    4_399_999_999, // These figures should be good for exactly this many years, including leap time
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

type EcdsaAlg = NistP384;
type EcdhAlg = NistP384;
type EcdhDigest = sha2::Sha384;
type EcdsaDigest = sha2::Sha384;

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

/// Processes a request with a symmetric algorithm chosen by the client from a list of algorithms.
/// 
/// This could be done with a hash algorithm as well as an elliptic curve, but that would take a bit more code. The easiest thing to do might be to make different versions of the same function using generic parameters.
/// 
/// # Arguments
/// 
/// * `key_manager` - the HttpPrivateKeyManager
/// * `func_to_call` - the function that will be called to process the inner content. It needs to take the following parameters and output a `DecryptedOutput`:
///   * `&mut HttpPrivateKeyManager`
///   * `DecryptedOutput` ($request)
///   * `$hasher`
/// * `request` - the request Protobuf Message
/// * `request_bytes` - the bytes of the Protobuf Request, used for hashing
/// * `response` - the response type
/// * `hasher` - the hash function to use for verifying the signature
/// * `decrypted_inner_request_type` - the inner request that `$func_to_call` is expecting as input
/// * `chosen_symmetric_alg` - the user's chosen symmetric encryption algorithm. `ChaCha20Poly1305` is faster on `aarch64`
/// * `is_handshake` - whether or not this request is supposed to be an initial handshake
/// * `(name, alg)` - a series of tuples of (str, ty) where the str is the string representation of the symmetric algorithm name, and the type is the AEAD type corresponding to the name
#[macro_export]
macro_rules! process_request_with_symmetric_algorithm {
    ($key_manager:expr, $func_to_call:ident, $request:expr, $request_bytes:expr, $signature:expr, $response:ty, $hasher:ty, $decrypted_inner_request_type:ty, $chosen_symmetric_alg:expr, $is_handshake:literal, $(($name:expr, $alg:ty)),*) => { {
            match $chosen_symmetric_alg {
                $(
                    $name => {
                        let (mut decrypted, hasher) = $key_manager.decrypt_and_hash_request::<$alg, $hasher, $decrypted_inner_request_type>($request, $request_bytes, $is_handshake)?;
                        
                        let mut output = $func_to_call(&mut $key_manager, &mut decrypted, hasher, $signature).await?;
                        
                        $key_manager.encrypt_and_sign_response::<$alg, $response>(&mut output)?
                    },
                )*
                _ => return Err(Box::new($crate::error::ApiError::InvalidRequest("Invalid symmetric encryption algorithm".into())))
            }
        }
    };
}

/// Initializes a Key manager. 
/// 
/// The key needs to be changed to something secure, and the initialization should probably be handled in conjunction with a `Box` or stack bleaching.
pub fn init_key_manager(kdf_key: Option<&[u8]>, alphabet: Option<&str>) -> KeyManager {
    KeyManager::from_key_generator(
        KeyGen::new(kdf_key.unwrap_or(&[32u8; 64]), b"plugin licensor"), 
        Alphabet::new(alphabet.unwrap_or("qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM/_")).unwrap()
    )
}

pub trait DigitalLicensingThemedKeymanager {
    /// Generates a license code for a user
    /// 
    /// # Arguments
    /// 
    /// * `store_id` - The store's ID
    /// * `product_id` - The plugin ID
    fn generate_license_code(&mut self, store_id: &Id<StoreId>, product_id: &Id<ProductId>) -> Result<Id<LicenseCode>, ApiError>;

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
    fn validate_license_code(&mut self, license_code: &str, store_id: &Id<StoreId>, product_id: &Id<ProductId>) -> Result<Id<LicenseCode>, ApiError>;

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
    fn validate_product_id(&mut self, product_id: &str, store_id: &Id<StoreId>) -> Result<(Id<ProductId>, SigningKey<EcdsaAlg>), ApiError>;

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

    /// Encrypts and zeroizes a `StoreDbItem`
    fn encrypt_store_db(&mut self, data: &StoreDbItem, store_id: &Id<StoreId>) -> Result<Vec<u8>, ApiError>;

    /// Decrypts a `StoreDbItem`
    fn decrypt_store_db(&mut self, data: &[u8], store_id: &Id<StoreId>) -> Result<StoreDbItem, ApiError>;
}

impl DigitalLicensingThemedKeymanager for KeyManager {
    #[inline]
    fn generate_license_code(&mut self, store_id: &Id<StoreId>, product_id: &Id<ProductId>) -> Result<Id<LicenseCode>, ApiError> {
        let associated_data = [store_id.binary_id.as_ref(), product_id.binary_id.as_ref()].concat();
        let mut id = self.key_generator.generate_keyless_id::<LicenseCode>(&[], b"license code", None, Some(&associated_data), &mut self.rng)?;

        let encoded_str = encode_to_hex_with_dashes(id.as_ref(), 5);
        let r = Ok(Id::new_from_vec(&id, encoded_str, associated_data));

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
    fn validate_license_code(&mut self, license_code: &str, store_id: &Id<StoreId>, product_id: &Id<ProductId>) -> Result<Id<LicenseCode>, ApiError> {
        let decoded = decode_hex::<LicenseCode>(license_code)?;

        let associated_data = [store_id.binary_id.as_ref(), product_id.binary_id.as_ref()].concat();

        let id = self.key_generator.validate_keyless_id::<LicenseCode>(&decoded, b"license code", Some(&associated_data))?;

        Ok(Id::new_from_vec(&id, license_code.to_string(), associated_data))
    }

    #[inline]
    fn validate_product_id(&mut self, product_id: &str, store_id: &Id<StoreId>) -> Result<(Id<ProductId>, SigningKey<EcdsaAlg>), ApiError> {
        let id = self.validate_ecdsa_key_id::<EcdsaAlg, ProductId>(product_id, Some(store_id.binary_id.as_ref()))?;
        let key = self.key_generator.generate_ecdsa_key_from_id::<EcdsaAlg, ProductId>(&id.binary_id, Some(store_id.binary_id.as_ref()));
        Ok((id, key))
    }

    #[inline]
    fn validate_store_id(&mut self, store_id: &str) -> Result<Id<StoreId>, ApiError> {
        Ok(self.validate_keyless_id::<StoreId>(store_id, b"Store ID", None)?)
    }

    #[inline]
    fn sign_key_file(&mut self, key_file: &[u8], product_id: &Id<ProductId>) -> Result<Vec<u8>, ApiError> {
        self.sign_data_with_key_id::<EcdsaAlg, ProductId, Sha3_384>(key_file, product_id)?;
        todo!()
    }

    #[inline]
    fn encrypt_store_db(&mut self, data: &StoreDbItem, store_id: &Id<StoreId>) -> Result<Vec<u8>, ApiError> {
        let mut encoded = data.encode_to_vec();

        let encrypted = self.encrypt_resource::<ChaCha20Poly1305>(encoded.as_slice(), STORES_TABLE.table_name.as_bytes(), store_id.binary_id.as_ref(), &[])?;
        
        #[cfg(feature = "zeroize")]
        encoded.zeroize();

        Ok(encrypted)
    }

    #[inline]
    fn decrypt_store_db(&mut self, data: &[u8], store_id: &Id<StoreId>) -> Result<StoreDbItem, ApiError> {
        let mut decrypted = self.decrypt_resource::<ChaCha20Poly1305>(data, STORES_TABLE.table_name.as_bytes(), store_id.binary_id.as_ref(), &[])?;

        let decoded = if let Ok(d) = StoreDbItem::decode(decrypted.as_slice()) {
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
        let license_code = key_manager.generate_license_code(&store_id, &plugin_id).unwrap();

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
        let license_code = key_manager.generate_license_code(&store_id, &plugin_id).unwrap();

        // validation, in the order that it will need to be validated in the real code
        // the encoded_ids will be given to developers, and the server will receive them in http requests
        let verified_store_id = key_manager.validate_store_id(&store_id.encoded_id);
        assert_eq!(verified_store_id.is_ok(), true);

        let store_id = verified_store_id.unwrap();
        let verified_plugin_id = key_manager.validate_product_id(&plugin_id.encoded_id, &store_id);
        assert_eq!(verified_plugin_id.is_ok(), true);

        let (plugin_id, _) = verified_plugin_id.unwrap();
        let verified_license = key_manager.validate_license_code(&license_code.encoded_id, &store_id, &plugin_id);
        assert_eq!(verified_license.is_ok(), true);
    }

    /// This test shows that private keys generated from Plugin/Product IDs are mostly unique, and that they can be regenerated fairly quickly... probably faster than you can pull one out of your database unless you're caching the database with something like AWS DAX clusters.
    #[test]
    fn assert_unique_and_regenerable_keys() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("testing").unwrap();
        let (plugin_id_1, key_1) = key_manager.generate_product_id("", &store_id).unwrap();
        let (plugin_id_2, key_2) = key_manager.generate_product_id("", &store_id).unwrap();

        // this test has an extremely small chance of failing, even if all the code is correct. Even if it did fail, it would not be as significant as the possibility of a malicious user decompiling the client-side code and swapping out the URL and public key, or even just cracking the client side DRM normally
        assert_ne!(key_1, key_2);

        // the encoded_ids will be given to developers, and the server will receive them in http requests
        let (_verified_plugin_id_1, regenned_key_1) = key_manager.validate_product_id(&plugin_id_1.encoded_id, &store_id).unwrap();
        assert_eq!(regenned_key_1.verifying_key().to_sec1_bytes(), key_1);

        let (_verified_plugin_id_2, regenned_key_2) = key_manager.validate_product_id(&plugin_id_2.encoded_id, &store_id).unwrap();
        assert_eq!(regenned_key_2.verifying_key().to_sec1_bytes(), key_2);
    }

    #[test]
    fn print_table_ids() {
        let mut key_manager = init_key_manager(None, None);
        let store_id = key_manager.generate_store_id("TEST Store").unwrap();
        let (plugin_id, _) = key_manager.generate_product_id("TEST plugin", &store_id).unwrap();
        let license_code = key_manager.generate_license_code(&store_id, &plugin_id).unwrap();

        // to print the IDs in a test:
        // cargo test -- --nocapture
        println!("Store ID = {}", store_id.encoded_id);
        println!("Plugin ID = {}", plugin_id.encoded_id);
        println!("License Code = {}", license_code.encoded_id);
        assert!(true)
    }
}