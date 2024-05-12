fn main() {
    prost_build::Config::new()
        .out_dir("src/protos")
        .compile_protos(
            &[
                "src/request_protos/register_store.proto",
                "src/response_protos/register_store.proto",
                "src/database_protos/store.proto"
                ], 
            &["src/"])
        .unwrap();
}