fn main() {
    println!("cargo:rerun-if-changed=ui/app.slint");
    if let Err(error) = slint_build::compile("ui/app.slint") {
        eprintln!("failed to compile the Slint UI: {error}");
        std::process::exit(1);
    }
}
