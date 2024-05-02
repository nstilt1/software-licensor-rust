use base64::{engine::general_purpose, DecodeError, Engine as _};

pub trait Base64Vec {
    fn to_base64(&self) -> String;
    fn from_base64(&self) -> Result<Vec<u8>, DecodeError>;
}

impl Base64Vec for [u8] {
    fn to_base64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(self)
    }

    fn from_base64(&self) -> Result<Vec<u8>, DecodeError> {
        general_purpose::STANDARD_NO_PAD.decode(self)
    }
}

impl Base64Vec for Vec<u8> {
    fn to_base64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(self)
    }
    fn from_base64(&self) -> Result<Vec<u8>, DecodeError> {
        general_purpose::STANDARD_NO_PAD.decode(self)
    }
}

pub trait Base64String {
    fn from_base64(&self) -> Result<Vec<u8>, DecodeError>;
}

impl Base64String for String {
    fn from_base64(&self) -> Result<Vec<u8>, DecodeError> {
        general_purpose::STANDARD_NO_PAD.decode(self)
    }
}

impl Base64String for &str {
    fn from_base64(&self) -> Result<Vec<u8>, DecodeError> {
        general_purpose::STANDARD_NO_PAD.decode(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_decode_roundtrip() {
        let input: Vec<u8> = vec![5, 3, 4, 5, 3, 3];
        let output = input.to_base64();
        let decoded = output.as_bytes().from_base64().unwrap();
        assert_eq!(input, decoded)
    }
}