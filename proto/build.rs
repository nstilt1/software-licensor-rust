fn main() {
    prost_build::Config::new()
        .out_dir("src/protos")
        .compile_protos(
            &[
                "src/request_protos/request.proto",
                "src/request_protos/response.proto",
                "src/request_protos/register_store.proto",
                "src/request_protos/create_product.proto",
                "src/request_protos/create_license.proto",
                "src/request_protos/license_activation.proto",
                "src/request_protos/get_license.proto",
                "src/request_protos/pubkeys.proto",
                "src/request_protos/deactivate_machines.proto",

                "src/database_protos/store.proto",
                "src/database_protos/product.proto",
                "src/database_protos/license.proto",
                ], 
            &["src/"])
        .unwrap();
}