# store the name of the lambda:
name=$1
# store the IAM number
iam=$2

# navigate to directory to add the new function
cd ..

# navigate to new directory
cd $name

# create builds directory
mkdir builds

# create deploy.sh
cat << EOF > deploy.sh
# find latest build file
cd builds
filename=\$(find . -maxdepth 1 -type f -printf "%f\n" | sort | tail -n 1)

aws lambda create-function --function-name ${name} \\
--handler bootstrap \\
--zip-file fileb://./\$filename \\
--runtime provided.al2 \\
--role ${iam} \\
--region us-east-1 \\
--architectures arm64
EOF

# make it executable
sudo chmod +x ./deploy.sh
