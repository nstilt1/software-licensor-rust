# name of the lambda
name=$1

./create_update_func_script.sh $name

cd ..
cd $name
mkdir builds

# create build.sh
cat << EOF > build.sh
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

if [ -z "\$1" ]; then
    echo "compiling without extra features"
    features_flag=""
else
    echo "compiling with features: \$1"
    features_flag="--features \$1"
fi

cross build --release \${features_flag} --target aarch64-unknown-linux-musl \
    && {
    timestamp=\$(date '+%y-%m-%d-%H-%M-%S')
    filename="\${timestamp}_\$1_${name}.zip"
    cd builds
    echo "creating \$filename..."
    mv ../../target/aarch64-unknown-linux-musl/release/${name} "bootstrap"
    zip -j "\$filename" ./"bootstrap"
    rm bootstrap
} || {
    echo "Build failed"
}
EOF

sudo chmod +x ./build.sh

# create build-zig.sh
cat << EOF > build-zig.sh
export RUSTFLAGS="--cfg chacha20_force_neon -Ctarget-cpu=neoverse-n1 -Ctarget-feature=+lse"

echo "COMPILING!!! Your compiled code will be ready in a moment"

# build

# GNU does not work at the moment
#cross build --release --features zeroize --target aarch64-unknown-linux-gnu \ 

if [ -z "\$1" ]; then
    echo "compiling without extra features"
    features_flag=""
else
    echo "compiling with features: \$1"
    features_flag="--features \$1"
fi

cargo lambda build --release --arm64 \${features_flag} \
    && {
    timestamp=\$(date '+%y-%m-%d-%H-%M-%S')
    filename="\${timestamp}_\$1_${name}.zip"
    cd builds
    echo "creating \$filename..."
    zip -j "\$filename" ../../target/lambda/${name}/bootstrap
} || {
    echo "Build failed"
}
EOF

sudo chmod +x ./build-zig.sh