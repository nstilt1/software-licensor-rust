use substring::Substring;

#[derive(Debug)]
pub struct HttpError {
    code: u16,
    message: String,
}

const debug_mode: bool = true;
const DEFAULT_ERROR_STATUS_CODE: u16 = 500;
impl HttpError {
    /**
     * Turns an error into a 202 error
     */
    pub fn _202(&self, new_error_message: &str) -> Self {
        let f_name = file!().substring(0, 3);
        HttpError {
            code: 202,
            message: format!(
                "We encountered an error, but your request went through. Error {}:{}", 
                new_error_message, 
                &self.message
            ),
        }
    }
}

pub mod new;
pub mod respond;
pub mod into;
pub mod from;