export RUSTFLAGS="-Ctarget-cpu=neoverse-n1"
export RUSTFLAGS="-Ctarget-feature=+lse"

echo "compiling"

# start docker if not started
ps -ef | grep -v grep | grep docker
if [ $? -eq 1 ]
then 
    sudo service docker start
    #sudo systemctl start docker
fi

# build
cross build --release --target aarch64-unknown-linux-musl
echo "creating create_plugin.zip..."
sudo zip -j create_plugin.zip ./target/aarch64-unknown-linux-musl/release/bootstrap