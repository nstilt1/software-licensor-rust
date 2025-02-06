export RUSTFLAGS="--cfg chacha20_force_neon -Ctarget-cpu=neoverse-n1 -Ctarget-feature=+lse"

echo "COMPILING!!! Your compiled code will be ready in a moment"

# build

# GNU does not work at the moment
#cross build --release --features zeroize --target aarch64-unknown-linux-gnu \ 

if [ -z "$1" ]; then
    echo "compiling without extra features"
    features_flag=""
else
    echo "compiling with features: $1"
    features_flag="--features $1"
fi

cargo lambda build --release --arm64 ${features_flag}     && {
    timestamp=$(date '+%y-%m-%d-%H-%M-%S')
    filename="${timestamp}_$1_link_store_admin.zip"
    cd builds
    echo "creating $filename..."
    zip -j "$filename" ../../target/lambda/link_store_admin/bootstrap
} || {
    echo "Build failed"
}
