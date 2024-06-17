# API Endpoints
* public keys are formatted with the Protobuf scheme found in `proto/src/request_protos/pubkeys.proto` at this URL:
  * https://software-licensor-public-keys.s3.amazonaws.com/public_keys
  * New keys are generated every 30 days, and the signing keys expire one year from the date they were created.
  * The ECDH public keys should only be used once, and a new public key will be sent with each response from the server.

# Limitations

This licensing API is currently limited to the following license types:

* Trial
* Subscription
* Perpetual

## Offline perpetual license limitiations

There isn't a way to remove/deactivate machines on a license (yet), but when there is a way to do that, there will be a conflict with Offline licenses. Offline licenses are licenses where a client computer will have an activated license *indefinitely* without needing to contact the server periodically to renew the license's expiration. That means that if someone had an offline computer with an offline license activated, then they *could "deactivate" this offline computer*, and since the offline computer won't talk to the server any more, the offline computer's license will remain activated forever. This could also happen if someone set up a firewall that blocked communication to the licensing service on the client's network or local machine.

There are a few ways to address this issue:

* use a physical device for offline licenses
  * we aren't like other competitors. we don't want to put the "plug in" in "plugin"
* disable deactivation for offline computers
  * this might be an inconvenience, and stores would have to inform users that this is a policy for the software licensing
* disallow offline licenses
  * it is possible to not have any Offline licenses for a product. It is an option in the `create_product` API method

There is also another policy that tries to limit this problem with malicious actors. In order to activate an offline license, the user needs to put `-offline-[4-hexadigit offline code]` at the end of their license code. If a legitimate customer shared a license code with someone, and that someone activated an offline license that *could not be removed/deactivated*, then the legitimate customer would permanently lose a machine slot on their license... or more, if someone were to do this with multiple computers.

## Subscription license limitations

Currently, subscription licenses can only have the base amount of machines using a license. This is because it is difficult to determine whether a subscription license `create_license` request is meant to *purchase* a new license, or if it is meant to *extend* an existing license. This can probably be broken up into 2 separate API methods: one for purchasing licenses, and one for extending subscriptions. *However*... IMO, if a person was willing to pay for a subscription for some amount of time and stopped paying... you have already earned as much as you might earn from this customer... why not let them keep their license, giving subscription license customers a perpetual license instead of a subscription license?

# Building

There are at least two ways to build this for the Graviton 2 processor using `cross` or `cargo-lambda`. `cargo-lambda` compiles a bit faster, but the files are a bit larger and the binaries run a little bit slower. `cargo-lambda` build scripts are saved as `build-cargo-lambda.sh` and the `cross` build scripts are saved as `build.sh`. You can also pass an argument that specifies the features to use. Available features are currently only `zeroize` and `logging`. Here's an example of how to call them:

```bash
./build.sh
# or
./build.sh "zeroize"
# or
./build.sh "zeroize,logging"
# or
./build-cargo-lambda.sh "zeroize,logging"
```

Note: `build-cargo-lambda.sh` requires `provided.al2023` for the Lambda function's runtime, not just `provided.al2`. The runtime is set to `provided.al2023` in the deployment scripts.

To build these API methods, you will need to install a few packages if you don't already have them installed:

* Install rust on Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

* Install openssl on Ubuntu:

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

* Install cargo lambda (optional, and its built binaries do not work at the moment)

```bash
rustup update
cargo install cargo-lambda
```

* Install Docker Desktop on your Host OS and enable its use in WSL if you are using WSL (highly recommended if you're on Windows). Or you can install `zig` using Homebrew on Linux/WSL.

* Install cross

```bash
cargo install cross
```

* Install `aarch64` build target:

```bash
rustup target add aarch64-unknown-linux-musl
```

* Install `aws-cli`:

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

## Setting up local environment variables:

Several environment variables need to be set for this to work:

1. KEY_MANAGER_PRIVATE_KEY - needs to be a minimum length of the key manager's hash function's output, and a maximum of the hash function's internal buffer. This is currently using `sha3_512` since it is faster on `aarch64` with inline assembly. So for this, ideally the length should be between 64-72 bytes (inclusive).

2. STORE_TABLE_SALT - a salt for the stores table

3. LICENSE_TABLE_SALT - a slat for the licenses table

Running the code on AWS requires setting each Lambda's environment variables.

# Getting this to work

There are a few things that you would need to do to get this to work, besides building it.

Here is a non-comprehensive list of what you would need to do to get the refactored version of the code to work:

1. make an AWS account if you do not have one
2. create some DynamoDB tables with table names, primary keys, and global secondary keys specified in `utils/src/tables/`, or change the names in those files to use different table names. You can generate some table names with `cargo test --features local -- --nocapture`. The long and random table names provide a little entropy when generating resource encryption keys when encrypting some of the data in the tables. It isn't completely necessary to have long table names, but AWS does not charge by the character in the table names. Yes, AWS supposedly encrypts the tables at rest, but why not add an extra layer of encryption? And, believe it or not, the encrypted protobuf messages can actually be smaller in size than putting it in plaintext NoSQL due to the potentially long keys since Protobuf keys are just binary numbers. The downside is that analytics tools such as AWS Athena likely will not be able to analyze any Protobuf/encrypted data.
3. Create an `IAM Role` that can read and write to these tables. This is best done by first creating an IAM Policy with DynamoDB permissions for BatchGetItem, GetItem, BatchWriteItem, UpdateItem, and PutItem. It will also need `S3>PutObject` permissions for a specific public keys bucket, which needs to be specified in the environment variables.
4. Create an `IAM user` with permissions for `Lambda>Create Function` and `IAM>Pass Role`, then make an access key for this user to sign into the AWS CLI with. Consider using `aws configure sso` instead, but that's a bit complicated and can break fairly easily.
5. Deploy the lambda functions. First, call `create_deployment_scripts`, specifying the `IAM Role` that can access the tables. Then call `build.sh` and `deploy.sh` to deploy the functions to the cloud. If anything changes, you need to call `update_func.sh` to update the functions.
6. Navigate to `API Gateway` and create an `HTTP API` or `REST API`. Do some research on the two, but you'll probably want a `REST API`. The differences are explained [here](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vs-rest.html)
7. Add the lambda functions to this API, and ensure that these API endpoints are accessible from the public internet.
8. Optionally, configure AWS WAF to restrict the (ab)usage of the API. You don't want to get DOS-ed.
9. Optionally, take `AWS Lambda Power Tuning` for a spin to potentially increase the speed and lower the cost of the lambda functions.