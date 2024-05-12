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
cross build --release --target aarch64-unknown-linux-musl
#cross build --target aarch64-unknown-linux-musl
timestamp=$(date '+%y-%m-%d-%H-%M-%S')
filename="create_plugin_${timestamp}.zip"
cd builds
echo "creating $filename..."
zip -j "$filename" "../../target/aarch64-unknown-linux-musl/release/create_plugin"
