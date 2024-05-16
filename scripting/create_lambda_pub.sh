

# store the name of the lambda:
name=$1
# store the IAM number
iam=$2

# navigate to directory to add the new function
cd ..

cargo lambda new $name

# navigate to new directory
cd $name

# create builds directory
mkdir builds

# create a temporary copy of insert.txt with the placeholder replaced
sed "s/{{name}}/$name/g" ../scripting/insert.txt > temp_insert.txt

# modify the Cargo.toml file
sed -i '5 r temp_insert.txt' Cargo.toml

# remove the temporary file
rm temp_insert.txt

EOF
    cd ..
    sed -i "1i mod modules;" main.rs
    sed -i "2i //use modules::module_name::*;" main.rs
    sed -i "3i //use modules::module_name::*;" main.rs
    cd ..
    

# create build.sh
cat << EOF > build.sh
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
timestamp=\$(date '+%y-%m-%d-%H-%M-%S')
filename="${name}_\${timestamp}.zip"
cd builds
echo "creating \$filename..."
zip -j "\$filename" "../../target/aarch64-unknown-linux-musl/release/${name}"
EOF

# make it executable
sudo chmod +x ./build.sh

# create deploy.sh
cat << EOF > deploy.sh
# find latest build file
cd builds
filename=\$(find . -maxdepth 1 -type f -printf "%f\n" | sort | tail -n 1)

aws lambda create-function --function-name ${name} \\
--handler bootstrap \\
--zip-file fileb://./\$filename \\
--runtime provided.al2 \\
--role arn:aws:iam::$iam for the Lambda Function \\
--region us-east-1 \\
--architectures arm64
EOF

# make it executable
sudo chmod +x ./deploy.sh

# create update_func.sh
cat << EOF > update_func.sh
# find latest build file
cd builds
filename=\$(find . -maxdepth 1 -type f -printf "%f\n" | sort | tail -n 1)

aws lambda update-function-code \\
--function-name ${name} \\
--zip-file fileb://./\$filename.zip \\
--region us-east-1
EOF

# make it executable
sudo chmod +x ./update_func.sh