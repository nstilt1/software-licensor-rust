use super::private::encrypt_id;
use substring::Substring;
pub fn decrypt_plugin_id (id: &str) -> String {
    let decrypted = encrypt_id(id, false, false);
    return decrypted.substring(decrypted.len()-11, decrypted.len()).to_owned();
}

pub fn encrypt_company_id(id: &str) -> String {
    return encrypt_id(id, true, false);
}

pub fn encrypt_plugin_id(company: &str, plugin: &str) -> String {
    return encrypt_id(&format!("{}{}", company, plugin), true, false);
}

pub fn decrypt_license_code(license_index: &str) -> String {
    let d = encrypt_id(license_index, false, false);
    return d.substring(d.len()-20, d.len()).to_owned();
}