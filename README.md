

# Building

Install rust on Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install openssl on Ubuntu:

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

Install cargo lambda

```bash
rustup update
cargo install cargo-lambda
```

Install cross

```bash
cargo install cross
```

Install `aarch64` build target:

```bash
rustup target add aarch64-unknown-linux-gnu
```

Install `aws-cli`:

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```