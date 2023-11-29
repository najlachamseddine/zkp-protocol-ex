fn main() {
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/")
        .compile(&["proto/zkp_auth.proto"], &["proto/"]) // proto/ to search for proto dependencies
        .unwrap();
}
