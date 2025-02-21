// Copyright 2020 Tyler Neely, Alex Regueiro
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::all)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(deref_nullptr)]

// Ensure the libraries are linked in, despite it not being used directly
#[cfg(feature = "bzip2")]
extern crate bzip2_sys;
#[cfg(feature = "zlib")]
extern crate libz_sys;
#[cfg(feature = "lz4")]
extern crate lz4_sys;
#[cfg(not(any(target_os = "openbsd")))]
extern crate openssl;
#[cfg(feature = "zstd")]
extern crate zstd_sys;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
