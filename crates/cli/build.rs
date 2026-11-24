//! Embeds the third-party notices in the binary, for `netbox-omnisync licenses`.
//!
//! `OMNISYNC_NOTICES` names the file `cargo about` generated; the release
//! build sets it (`scripts/release-build.sh`). Without it the binary embeds
//! none and says so: a plain `cargo build` needs neither the tool nor the file.

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=OMNISYNC_NOTICES");
    let notices = match env::var_os("OMNISYNC_NOTICES") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            // A release must not ship without them: a missing or empty file fails the build.
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("OMNISYNC_NOTICES: cannot read {}: {error}", path.display()));
            assert!(!text.trim().is_empty(), "OMNISYNC_NOTICES: {} is empty", path.display());
            text
        }
        None => String::new(),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("notices.txt");
    fs::write(&out, notices).unwrap_or_else(|error| panic!("cannot write {}: {error}", out.display()));
}
