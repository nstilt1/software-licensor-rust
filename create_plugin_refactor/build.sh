export RUSTFLAGS="-Ctarget-cpu=neoverse-n1 -Ctarget-feature=+lse"

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
    filename="${timestamp}_$1_create_plugin_refactor.zip"
    cd builds
    echo "creating $filename..."
    zip -j "$filename" "../../target/aarch64-unknown-linux-musl/release/create_plugin_refactor"
} || {
    echo "Build failed"
}
