// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Installs the bundled recursion programs for proof generation.
fn main() {
    #[cfg(feature = "prove")]
    install_recursion_programs();
}

#[cfg(feature = "prove")]

// Implements install recursion programs.
fn install_recursion_programs() {
    use std::{env, fs, io::{Read, Write}, path::PathBuf};
    use sha2::{Digest, Sha256};
    const EXPECTED: &str = "91ae9850d13b5866e60c918bc21f4f7f3397ed72b80e35fa10139dc0303cf875";
    let directory = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("src");
    let target = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("recursion_zkr.zip");
    println!("cargo:rerun-if-env-changed=RECURSION_SRC_PATH");
    let parts: Vec<_> = (0..23).map(|index| directory.join(format!("recursion_zkr.part{index:02}"))).collect();
    for part in &parts {
        println!("cargo:rerun-if-changed={}", part.display());
    }
    if env::var_os("DOCS_RS").is_some() {
        fs::write(target, []).unwrap();
        return;
    }
    if target.exists() && hex::encode(Sha256::digest(fs::read(&target).unwrap())) == EXPECTED {
        return;
    }
    let pending = target.with_extension("pending");
    let mut output = fs::File::create(&pending).unwrap();
    let mut digest = Sha256::new();
    let sources = env::var_os("RECURSION_SRC_PATH").map(PathBuf::from).map(|path| vec![path]).unwrap_or(parts);
    let mut buffer = vec![0u8; 1024 * 1024];
    for source in sources {
        let mut input = fs::File::open(&source).unwrap_or_else(|error| panic!("cannot read recursion programs at {}: {error}", source.display()));
        loop {
            let count = input.read(&mut buffer).unwrap();
            if count == 0 { break; }
            digest.update(&buffer[..count]);
            output.write_all(&buffer[..count]).unwrap();
        }
    }
    assert_eq!(hex::encode(digest.finalize()), EXPECTED, "recursion program checksum mismatch");
    output.flush().unwrap();
    drop(output);
    if target.exists() { fs::remove_file(&target).unwrap(); }
    fs::rename(pending, target).unwrap();
}
