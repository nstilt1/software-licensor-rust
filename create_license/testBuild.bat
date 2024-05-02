set OPENSSL_LIB_DIR=C:\Program Files\OpenSSL-Win64\lib
set OPENSSL_INCLUDE_DIR=C:\Program Files\OpenSSL-Win64\include

set OPENSSL_NO_VENDOR=1
set RUSTFLAGS=-Ctarget-feature=+crt-static
set SSL_CERT_FILE=C:\OpenSSL-Win64\certs\cacert.pem

cargo build

@echo off
echo Batch script complete
pause