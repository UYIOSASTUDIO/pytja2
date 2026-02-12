fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true) // Wir brauchen Server Code
        .build_client(true) // Wir brauchen Client Code (WICHTIG!)
        .compile(&["proto/pytja.proto"], &["proto"])?;
    Ok(())
}