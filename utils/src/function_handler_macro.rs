#[macro_export]
macro_rules! impl_function_handler {
    ($request_type:ty, $response_type:ty, $error_type:ty, $is_handshake:literal) => {
        // set global allocator for increased performance
        #[cfg(not(target_env = "msvc"))]
        use jemallocator::Jemalloc;

        #[cfg(not(target_env = "msvc"))]
        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;
        
        impl_handle_crypto!(
            $request_type,
            $response_type,
            $error_type,
            $crate::crypto::EcdsaDigest,
            $crate::crypto::Signature,
            ("chacha20-poly1305", ChaCha20Poly1305),
            ("aes-128-gcm", Aes128Gcm),
            ("aes-256-gcm", Aes256Gcm)
        );
        async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
            debug_log!("In function_handler");
            if event.query_string_parameters_ref().is_some() {
                return ApiError::InvalidRequest("Query string parameters are forbidden.".into()).respond();
            }
            let signature = if let Some(s) = event.headers().get("X-Signature") {
                match s.as_bytes().from_base64() {
                    Ok(v) => v,
                    Err(e) => return ApiError::InvalidRequest("The X-Signature header needs to contain base64 data.".into()).respond()
                }
            } else {
                return ApiError::InvalidRequest("Signature must be base64 encoded in the X-Signature header".into()).respond()
            };
            let request_bytes = if let Body::Binary(contents) = event.body() {
                contents
            } else {
                return ApiError::InvalidRequest("Body could not be read as binary".into()).respond()
            };

            let mut key_manager = init_key_manager(None, None);
            debug_log!("Initialized key_manager");

            let crypto_result = handle_crypto(&mut key_manager, request_bytes, $is_handshake, signature).await;
            let (encrypted, signature) = match crypto_result {
                Ok(v) => v,
                Err(e) => return e.respond()
            };

            let resp = Response::builder()
                .status(200)
                .header("content-type", "application/x-protobuf")
                .header("X-Signature-Info", "Algorithm: Sha2-384 + NIST-P384")
                .header("X-Signature", signature.to_der().as_bytes().to_base64(false))
                .body(encrypted.encode_length_delimited_to_vec().into())
                .expect("Unable to build http::Response");
            debug_log!("Built response");
            Ok(resp)
        }
        #[tokio::main]
        async fn main() -> Result<(), Error> {
            tracing::init_default_subscriber();
            run(service_fn(function_handler)).await
        }
    };
}