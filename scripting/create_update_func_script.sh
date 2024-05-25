# name of the lambda
name=$1

cd ..
cd $name

# create update_func.sh
cat << EOF > update_func.sh
# find latest build file
cd builds
filename=\$(find . -maxdepth 1 -type f -printf "%f\n" | sort | tail -n 1)

aws lambda update-function-code \\
--function-name ${name} \\
--zip-file fileb://./\$filename \\
--region us-east-1
EOF

# make it executable
sudo chmod +x ./update_func.sh