# store the IAM number
iam=$1

cd scripting
./create_deployment_script.sh "register_store_refactor" $iam
./create_deployment_script.sh "create_plugin_refactor" $iam
./create_deployment_script.sh "create_license_refactor" $iam
./create_deployment_script.sh "license_activation_refactor" $iam
./create_deployment_script.sh "publish_rotating_keys" $iam