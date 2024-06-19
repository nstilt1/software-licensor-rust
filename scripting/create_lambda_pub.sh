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

# create build scripts
cd ../scripting
./create_build_script.sh $name

# create update_func.sh
./create_update_func_script.sh