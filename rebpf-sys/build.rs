// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let out_dir_str = out_dir.to_str().unwrap();

    if cfg!(target_os = "linux") {
        // compile libbpf library
        let status = Command::new("make")
            .arg("install")
            .env("BUILD_STATIC_ONLY", "y")
            .env("PREFIX", "/")
            .env("LIBDIR", "")
            .env("OBJDIR", out_dir.join("obj").to_str().unwrap())
            .env("DESTDIR", out_dir_str)
            .env("CFLAGS", "-g -O2 -Werror -Wall -fPIC")
            .current_dir(src_dir.join("libbpf/src"))
            .status()
            .unwrap();
        assert!(status.success());

        let status = Command::new("make")
            .arg("clean")
            .current_dir(src_dir.join("libbpf/src"))
            .status()
            .unwrap();
        assert!(status.success());

        cc::Build::new()
            .file("libbpf_sys.c")
            .include(src_dir.join("libbpf/include"))
            .include(src_dir.join("libbpf/include/uapi"))
            .warnings(false)
            .flag("-O2")
            .out_dir(out_dir_str)
            .compile("libbpf_sys.rs");

        // create libbpf rust binding in OUT_DIR
        // _create_binding("libbpf_sys");
        
        // create bpf_sys rust binding in OUT_DIR
        // _create_binding("bpf_sys");

        println!("cargo:rustc-link-search=native={}", out_dir_str);
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=static=bpf");

    }
}

fn _create_binding(name: &str) {
    let bind = bindgen::Builder::default()
    // The input header we would like to generate
    // bindings for.
        .header(&format!("{}.h", name))
        .layout_tests(false)
    // Tell cargo to invalidate the built crate whenever any of the
    // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    // Finish the builder and generate the bindings.
        .generate()
    // Unwrap the Result and panic on failure.
        .expect(&format!("Unable to generate {}", name));

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bind
        .write_to_file(out_path.join(&format!("{}.rs", name)))
        .expect(&format!("Couldn't write {} binding!", name));    
}
