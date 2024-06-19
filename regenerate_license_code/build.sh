export RUSTFLAGS="--cfg chacha20_force_neon -Ctarget-cpu=neoverse-n1 -Ctarget-feature=+lse"

echo "COMPILING!!! Your compiled code will be ready in a moment"

# start docker if not started
if ! pgrep -x "docker" > /dev/null; then
    sudo service docker start
fi

# systemctl version
#if ! systemctl is-active --quiet docker; then
#    sudo systemctl start docker
#fi

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

cross build --release ${features_flag} --target aarch64-unknown-linux-musl     && {
    timestamp=$(date '+%y-%m-%d-%H-%M-%S')
    filename="${timestamp}_$1_regenerate_license_code.zip"
    cd builds
    echo "creating $filename..."
    mv ../../target/aarch64-unknown-linux-musl/release/regenerate_license_code "bootstrap"
    zip -j "$filename" ./"bootstrap"
    rm bootstrap
} || {
    echo "Build failed"
}
