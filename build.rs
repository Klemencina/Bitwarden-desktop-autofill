fn main() {
    // Only run on Windows
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();

        // Embed the application manifest
        res.set_manifest_file("app.manifest");

        // Set application icon (optional - uncomment if you have an icon)
        // res.set_icon("app.ico");

        // Compile and link the resource
        if let Err(e) = res.compile() {
            eprintln!("Failed to compile Windows resources: {}", e);
            // Don't fail the build, just warn
        }
    }
}
