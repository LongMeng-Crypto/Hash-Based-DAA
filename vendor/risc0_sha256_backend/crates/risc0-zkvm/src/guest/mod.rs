// Copyright 2024 RISC Zero, Inc.
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

//! The RISC Zero zkVM's guest-side RISC-V API.
//!
//! Code that is validated by the [RISC Zero zkVM](crate) is run inside the guest. In almost all
//! practical cases, the guest will want to read private input data from the host and write public
//! data to the journal. This can be done with [env::read] and [env::commit], respectively;
//! additional I/O functionality is also available in [mod@env].
//!
//! ## Installation
//!
//! To build and run RISC Zero zkVM code, you will need to install the RISC Zero
//! toolchain, which can be done using the rzup utility:
//!
//! ```sh
//! curl -L https://risczero.com/install | bash
//! rzup install
//! ```
//!
//! ## Example
//!
//! The following guest code[^starter-ex] proves a number is
//! composite by multiplying two unsigned integers, and panicking if either is
//! `1` or if the multiplication overflows:
//!
//! ```ignore
//! #![no_main]
//! #![no_std]
//!
//! use risc0_zkvm::guest::env;
//!
//! risc0_zkvm::guest::entry!(main);
//!
//! fn main() {
//!     // Load the first number from the host
//!     let a: u64 = env::read();
//!     // Load the second number from the host
//!     let b: u64 = env::read();
//!     // Verify that neither of them are 1 (i.e. nontrivial factors)
//!     if a == 1 || b == 1 {
//!         panic!("Trivial factors")
//!     }
//!     // Compute the product while being careful with integer overflow
//!     let product = a.checked_mul(b).expect("Integer overflow");
//!     env::commit(&product);
//! }
//! ```
//!
//! Notice how [env::read] is used to load the two factors, and [env::commit] is used to make their
//! composite product publicly available. All input an output of your guest is private except for
//! what is written to the journal with [env::commit].
//!
//! By default, the guest only has the Rust `core` libraries and not `std`. A partial
//! implementation of the Rust standard libraries can be enabled with the `std` feature on this [crate].
//! When this feature is not enabled, the lines including `#![no_std]` and `#![no_main]` are
//! required, as well as the use of the [crate::guest::entry] macro. When `std` is enabled, these
//! three lines can be omitted and many features of `std` can be used.
//!
//! If you encounter problems building zkVM guest code, you can see if we have a
//! known workaround for your issue by looking in our
//! [rust guest workarounds](https://github.com/risc0/risc0/issues?q=is%3Aissue+is%3Aopen+label%3A%22rust+guest+workarounds%22)
//! tag on GitHub.
//!
//! [^starter-ex]: The example is based on the [Factors example](https://github.com/risc0/risc0/tree/main/examples/factors).

#![allow(missing_docs)]

pub mod env;

#[cfg(target_os = "zkvm")]
use core::arch::asm;

use risc0_zkvm_platform::syscall::sys_panic;

pub use risc0_zkp::core::hash::sha;

pub use crate::entry;

#[cfg(target_os = "zkvm")]
core::arch::global_asm!(include_str!("memset.s"));
#[cfg(target_os = "zkvm")]
core::arch::global_asm!(include_str!("memcpy.s"));

// Implements fault.
fn _fault() -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!("sw x0, 1(x0)")
    };
    unreachable!();
}

// Implements abort.
pub fn abort(msg: &str) -> ! {

    unsafe {
        sys_panic(msg.as_ptr(), msg.len());
    }
}

#[macro_export]
macro_rules! entry {
    ($path:path) => {

        const ZKVM_ENTRY: fn() = $path;

        mod zkvm_generated_main {
            #[no_mangle]

            // Implements main.
            fn main() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

#[cfg(target_os = "zkvm")]
#[no_mangle]

// Implements start.
unsafe extern "C" fn __start() -> ! {
    risc0_zkvm_platform::heap::init();
    env::init();

    {
        extern "C" {

            // Implements main.
            fn main();
        }
        main()
    }

    env::finalize(true, 0);
    unreachable!();
}

#[cfg(target_os = "zkvm")]
static STACK_TOP: u32 = risc0_zkvm_platform::memory::STACK_TOP;

#[cfg(target_os = "zkvm")]
core::arch::global_asm!(
    r#"
.section .text._start;
.globl _start;
_start:
    .option push;
    .option norelax;
    la gp, __global_pointer$;
    .option pop;
    la sp, {0}
    lw sp, 0(sp)
    call __start;
"#,
    sym STACK_TOP
);

#[allow(unused_variables)]

// Implements memory barrier.
pub fn memory_barrier<T>(ptr: *const T) {

    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!("/* {0} */", in(reg) (ptr))
    }
    #[cfg(not(target_os = "zkvm"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst)
}

#[cfg(all(target_os = "zkvm", not(feature = "std")))]
#[panic_handler]

// Implements panic impl.
fn panic_impl(panic_info: &core::panic::PanicInfo) -> ! {
    risc0_zkvm_platform::rust_rt::panic_fault(panic_info);
}
