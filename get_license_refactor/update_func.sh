# find latest build file
cd builds
filename=$(find . -maxdepth 1 -type f -printf "%f\n" | sort | tail -n 1)

aws lambda update-function-code \
--function-name get_license_refactor \
--zip-file fileb://./$filename \
--region us-east-1
