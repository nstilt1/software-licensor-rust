fn main() {
    prost_build::Config::new()
        .out_dir("src/protos")
        .compile_protos(
            &[
                "src/request_protos/register_store.proto",
                "src/request_protos/create_product.proto",
                "src/request_protos/create_license.proto",
                "src/response_protos/register_store.proto",
                "src/response_protos/create_product.proto",
                "src/response_protos/create_license.proto",
                "src/database_protos/store.proto",
                //"src/database_protos/product.proto",
                ], 
            &["src/"])
        .unwrap();
}