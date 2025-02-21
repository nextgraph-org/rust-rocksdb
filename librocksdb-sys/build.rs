use std::path::Path;
use std::{env, fs, path::PathBuf, process::Command};

fn link(name: &str, bundled: bool) {
    use std::env::var;
    let target = var("TARGET").unwrap();
    let target: Vec<_> = target.split('-').collect();
    if target.get(2) == Some(&"windows") {
        println!("cargo:rustc-link-lib=dylib={name}");
        if bundled && target.get(3) == Some(&"gnu") {
            let dir = var("CARGO_MANIFEST_DIR").unwrap();
            println!("cargo:rustc-link-search=native={}/{}", dir, target[0]);
        }
    } else if target.get(2) == Some(&"darwin") {
        println!("cargo:rustc-link-arg=-mmacosx-version-min=10.14");
    }
}

fn fail_on_empty_directory(name: &str) {
    if fs::read_dir(name).unwrap().count() == 0 {
        println!("The `{name}` directory is empty, did you forget to pull the submodules?");
        println!("Try `git submodule update --init --recursive`");
        panic!();
    }
}

fn rocksdb_include_dir() -> String {
    match env::var("ROCKSDB_INCLUDE_DIR") {
        Ok(val) => val,
        Err(_) => "librocksdb-sys/rocksdb/include".to_string(),
    }
}

fn bindgen_rocksdb() {
    let bindings = bindgen::Builder::default()
        .header(rocksdb_include_dir() + "/rocksdb/c.h")
        .header("librocksdb-sys/api/c.h")
        .derive_debug(false)
        .blocklist_type("max_align_t") // https://github.com/rust-lang-nursery/rust-bindgen/issues/550
        .ctypes_prefix("libc")
        .size_t_is_usize(true)
        .allowlist_function("rocksdb_.*")
        .allowlist_type("rocksdb_.*")
        .allowlist_var("rocksdb_.*")
        .generate()
        .expect("unable to generate rocksdb bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write rocksdb bindings");
}

fn build_rocksdb() {
    let target = env::var("TARGET").unwrap();

    let mut config = cc::Build::new();
    config.include("librocksdb-sys/rocksdb/include/");
    config.include("librocksdb-sys/rocksdb/");
    config.include("librocksdb-sys/rocksdb/third-party/gtest-1.8.1/fused-src/");

    if cfg!(feature = "snappy") {
        config.define("SNAPPY", Some("1"));
        if let Some(path) = env::var_os("DEP_SNAPPY_INCLUDE") {
            config.include(path);
        }
    }

    if cfg!(feature = "lz4") {
        config.define("LZ4", Some("1"));
        config.include("librocksdb-sys/lz4/");
    }

    if cfg!(feature = "zstd") {
        config.define("ZSTD", Some("1"));
        if let Some(path) = env::var_os("DEP_ZSTD_INCLUDE") {
            config.include(path);
        }
    }

    if cfg!(feature = "zlib") {
        config.define("ZLIB", Some("1"));
        if let Some(path) = env::var_os("DEP_Z_INCLUDE") {
            config.include(path);
        }
    }

    if cfg!(feature = "bzip2") {
        config.define("BZIP2", Some("1"));
        if let Some(path) = env::var_os("DEP_BZIP2_INCLUDE") {
            config.include(path);
        }
    }

    if cfg!(feature = "rtti") {
        config.define("USE_RTTI", Some("1"));
    }

    config.include("librocksdb-sys");
    config.define("NDEBUG", Some("1"));

    let mut lib_sources = include_str!("rocksdb_lib_sources.txt")
        .trim()
        .split('\n')
        .map(str::trim)
        // We have a pre-generated a version of build_version.cc in the local directory
        .filter(|file| !matches!(*file, "util/build_version.cc"))
        .collect::<Vec<&'static str>>();

    if let (true, Ok(_target_feature_value)) = (
        target.contains("x86_64"),
        env::var("CARGO_CFG_TARGET_FEATURE"),
    ) {
        // This is needed to enable hardware CRC32C. Technically, SSE 4.2 is
        // only available since Intel Nehalem (about 2010) and AMD Bulldozer
        // (about 2011).
        // let target_features: Vec<_> = target_feature_value.split(',').collect();

        // if target_features.contains(&"sse2") {
        //     config.flag_if_supported("-msse2");
        // }
        // if target_features.contains(&"sse4.1") {
        //     config.flag_if_supported("-msse4.1");
        // }
        // if target_features.contains(&"sse4.2") {
        //     config.flag_if_supported("-msse4.2");
        // }
        // // Pass along additional target features as defined in
        // // build_tools/build_detect_platform.
        // if target_features.contains(&"avx2") {
        //     config.flag_if_supported("-mavx2");
        // }
        // if target_features.contains(&"bmi1") {
        //     config.flag_if_supported("-mbmi");
        // }
        // if target_features.contains(&"lzcnt") {
        //     config.flag_if_supported("-mlzcnt");
        // }
        // if !target.contains("android") && target_features.contains(&"pclmulqdq") {
        //     config.flag_if_supported("-mpclmul");
        // }

        // We want a portable library that can run on any x86_64.
        // but we optimize for haswell which supports
        // many or most of the available optimizations while still being compatible with
        // most processors made since roughly 2013.
        // if this becomes a problem for some app installers with older hardware, a special install
        // file should be generated with a lib compiled without this flag
        // config.flag("-march=haswell");
        // the flag has been moved to the darwin. openbsd, freebsd and linux cases below
    }

    // if target.contains("darwin") || (target.contains("linux") && !target.contains("android")) {
    //     // on macos and linux we use the IPPCP plugin of rocksdb for the crypto (the lib is precompiled)
    //     config.include("librocksdb-sys/rocksdb/plugin/ippcp/library/include");
    //     lib_sources.push("plugin/ippcp/ippcp_provider.cc");
    //     let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    //     let prebuild_lib = if target.contains("darwin") {
    //         "macos"
    //     } else {
    //         "linux"
    //     };
    //     println!(
    //         "cargo:rustc-link-search=native={}",
    //         Path::new(&dir)
    //             .join(format!(
    //                 "librocksdb-sys/rocksdb/plugin/ippcp/library/{prebuild_lib}/lib"
    //             ))
    //             .display()
    //     );
    //     println!("cargo:rustc-link-lib=static=ippcp");
    // } else
    if !target.contains("openbsd") {
        if let Some(include) = std::env::var_os("DEP_OPENSSL_INCLUDE") {
            config.include(include);
        } else {
            config.include("librocksdb-sys/rocksdb/plugin/openssl/include");
        }
        lib_sources.push("plugin/openssl/openssl_provider.cc");
        // let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        // println!(
        //     "cargo:rustc-link-search=dependency={}",
        //     Path::new(&dir)
        //         //.join("rocksdb/plugin/ippcp/library/macos/lib")
        //         .display()
        // );
        // println!("cargo:rustc-link-lib=static=crypto");
    }

    if target.contains("apple-ios") {
        config.define("OS_MACOSX", None);
        config.define("IOS_CROSS_COMPILE", None);
        config.define("PLATFORM", "IOS");
        config.define("NIOSTATS_CONTEXT", None);
        config.define("NPERF_CONTEXT", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        env::set_var("IPHONEOS_DEPLOYMENT_TARGET", "12.0");
    } else if target.contains("darwin") {
        if !target.contains("aarch64-apple-darwin") {
            config.flag("-march=haswell");
        }
        config.define("OS_MACOSX", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        println!("cargo:rustc-link-arg=-mmacosx-version-min=10.14");
        config.flag("-Wshorten-64-to-32");
        config.flag("-mmacosx-version-min=10.14");
        config.define("DHAVE_FULLFSYNC", None);
        config.define("HAVE_UINT128_EXTENSION", None);
        config.flag_if_supported("-faligned-new");
        config.define("AVE_ALIGNED_NEW", None);
    } else if target.contains("android") {
        config.define("OS_ANDROID", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        config.define("OPENSSL_NO_STDIO", None);
        config.define("ANDROID_STL", "c++_shared");
        config.define("_REENTRANT", None);
        config.flag("-fno-builtin-memcmp");
    } else if target.contains("linux") {
        config.flag("-march=haswell");
        config.define("OS_LINUX", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        config.define("ROCKSDB_FALLOCATE_PRESENT", None);
        config.define("ROCKSDB_MALLOC_USABLE_SIZE", None);
        config.define("ROCKSDB_PTHREAD_ADAPTIVE_MUTEX", None);
        config.define("ROCKSDB_RANGESYNC_PRESENT", None);
        config.define("ROCKSDB_SCHED_GETCPU_PRESENT", None);
        config.define("ROCKSDB_AUXV_GETAUXVAL_PRESENT", None);
        config.define("HAVE_UINT128_EXTENSION", None);
        config.define("HAVE_ALIGNED_NEW", None);
        println!("cargo:rustc-link-arg=-lpthread");
        println!("cargo:rustc-link-arg=-lrt");
        println!("cargo:rustc-link-arg=-ldl");
        config.flag("-fno-builtin-memcmp");
    } else if target.contains("freebsd") {
        config.flag("-march=haswell");
        config.define("OS_FREEBSD", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        println!("cargo:rustc-link-arg=-lpthread");
        config.flag("-fno-builtin-memcmp");
        config.define("_REENTRANT", None);
    } else if target.contains("openbsd") {
        //config.flag("-march=haswell");
        config.define("OS_OPENBSD", None);
        config.define("ROCKSDB_PLATFORM_POSIX", None);
        config.define("ROCKSDB_LIB_IO_POSIX", None);
        //config.define("ZLIB", None);
        println!("cargo:rustc-link-arg=-pthread");
        println!("cargo:rustc-link-lib=execinfo");
        //println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=crypto");
        config.flag("-fno-builtin-memcmp");
        config.flag_if_supported("-faligned-new");
        config.flag("-Wshorten-64-to-32");
        config.define("ROCKSDB_BACKTRACE", None);
        config.define("HAVE_UINT128_EXTENSION", None);
        config.define("DHAVE_ALIGNED_NEW", None);
        config.define("_REENTRANT", None);
        config.include("librocksdb-sys/rocksdb/plugin/openssl/include");
        lib_sources.push("plugin/openssl/openssl_provider.cc");
    } else if target.contains("windows") {
        link("rpcrt4", false);
        link("shlwapi", false);
        config.define("DWIN32", None);
        config.define("OS_WIN", None);
        config.define("_MBCS", None);
        config.define("WIN64", None);
        config.define("NOMINMAX", None);
        config.define("ROCKSDB_WINDOWS_UTF8_FILENAMES", None);

        // Got some errors while using IPPCP plugin on windows.
        // switching to openssl

        // let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        // println!(
        //     "cargo:rustc-link-search=native={}",
        //     Path::new(&dir)
        //         .join("rocksdb/plugin/ippcp/library/win")
        //         .display()
        // );
        // println!("cargo:rustc-link-lib=static=ippcpmt");

        if &target == "x86_64-pc-windows-gnu" {
            // Tell MinGW to create localtime_r wrapper of localtime_s function.
            config.define("_POSIX_C_SOURCE", Some("1"));
            // Tell MinGW to use at least Windows Vista headers instead of the ones of Windows XP.
            // (This is minimum supported version of rocksdb)
            config.define("_WIN32_WINNT", Some("_WIN32_WINNT_VISTA"));
        }

        // Remove POSIX-specific sources
        lib_sources = lib_sources
            .iter()
            .cloned()
            .filter(|file| {
                !matches!(
                    *file,
                    "port/port_posix.cc"
                        | "env/env_posix.cc"
                        | "env/fs_posix.cc"
                        | "env/io_posix.cc"
                )
            })
            .collect::<Vec<&'static str>>();

        // Add Windows-specific sources
        lib_sources.extend([
            "port/win/env_default.cc",
            "port/win/port_win.cc",
            "port/win/xpress_win.cc",
            "port/win/io_win.cc",
            "port/win/win_thread.cc",
            "port/win/env_win.cc",
            "port/win/win_logger.cc",
        ]);

        if cfg!(feature = "jemalloc") {
            lib_sources.push("port/win/win_jemalloc.cc");
        }
    }

    config.define("ROCKSDB_SUPPORT_THREAD_LOCAL", None);

    if cfg!(feature = "jemalloc") {
        config.define("WITH_JEMALLOC", "ON");
    }

    #[cfg(feature = "io-uring")]
    if target.contains("linux") {
        pkg_config::probe_library("liburing")
            .expect("The io-uring feature was requested but the library is not available");
        config.define("ROCKSDB_IOURING_PRESENT", Some("1"));
    }

    if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() != "64" {
        config.define("_FILE_OFFSET_BITS", Some("64"));
        config.define("_LARGEFILE64_SOURCE", Some("1"));
    }

    if target.contains("msvc") {
        config.flag("-EHsc");
        config.flag("-std:c++17");
        //  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi /nologo /EHsc /GS /Gd /GR /GF /fp:precise /Zc:wchar_t /Zc:forScope /errorReport:queue")
        // set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /FC /d2Zi+ /W4 /wd4127 /wd4800 /wd4996 /wd4351 /wd4100 /wd4204 /wd4324")
    } else {
        if target.contains("x86_64") {
            config.flag_if_supported("-Wstrict-prototypes");
        }
        //-W -Wextra -Wall -pthread
        //-fno-omit-frame-pointer
        //-momit-leaf-frame-pointer
        config.flag(&cxx_standard());
        // matches the flags in CMakeLists.txt from rocksdb
        config.flag("-Wsign-compare");
        config.flag("-Wshadow");
        config.flag("-Wno-unused-parameter");
        config.flag("-Wno-unused-variable");
        config.flag("-Woverloaded-virtual");
        config.flag("-Wnon-virtual-dtor");
        config.flag("-Wno-missing-field-initializers");
        config.flag("-Wno-strict-aliasing");
        config.flag("-Wno-invalid-offsetof");
    }

    for file in lib_sources {
        config.file(format!("librocksdb-sys/rocksdb/{file}"));
    }

    config.file("librocksdb-sys/build_version.cc");
    config.file("librocksdb-sys/api/c.cc");

    config.cpp(true);
    config.flag_if_supported("-std=c++17");

    config.compile("librocksdb.a");
}

fn build_snappy() {
    let target = env::var("TARGET").unwrap();
    let endianness = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let mut config = cc::Build::new();

    config.include("snappy/");
    config.include(".");
    config.define("NDEBUG", Some("1"));
    config.extra_warnings(false);

    if target.contains("msvc") {
        config.flag("-EHsc");
    } else {
        // Snappy requires C++11.
        // See: https://github.com/google/snappy/blob/master/CMakeLists.txt#L32-L38
        config.flag("-std=c++11");
    }

    if endianness == "big" {
        config.define("SNAPPY_IS_BIG_ENDIAN", Some("1"));
    }

    config.file("snappy/snappy.cc");
    config.file("snappy/snappy-sinksource.cc");
    config.file("snappy/snappy-c.cc");
    config.cpp(true);
    config.compile("libsnappy.a");
}

fn try_to_find_and_link_lib(lib_name: &str) -> bool {
    println!("cargo:rerun-if-env-changed={lib_name}_COMPILE");
    if let Ok(v) = env::var(format!("{lib_name}_COMPILE")) {
        if v.to_lowercase() == "true" || v == "1" {
            return false;
        }
    }

    println!("cargo:rerun-if-env-changed={lib_name}_LIB_DIR");
    println!("cargo:rerun-if-env-changed={lib_name}_STATIC");

    if let Ok(lib_dir) = env::var(format!("{lib_name}_LIB_DIR")) {
        println!("cargo:rustc-link-search=native={lib_dir}");
        let mode = match env::var_os(format!("{lib_name}_STATIC")) {
            Some(_) => "static",
            None => "dylib",
        };
        println!("cargo:rustc-link-lib={}={}", mode, lib_name.to_lowercase());
        return true;
    }
    false
}

fn cxx_standard() -> String {
    env::var("ROCKSDB_CXX_STD").map_or("-std=c++17".to_owned(), |cxx_std| {
        if !cxx_std.starts_with("-std=") {
            format!("-std={cxx_std}")
        } else {
            cxx_std
        }
    })
}

#[allow(dead_code)]
fn update_submodules() {
    let program = "git";
    let dir = "../";
    let args = ["submodule", "update", "--init"];
    println!(
        "Running command: \"{} {}\" in dir: {}",
        program,
        args.join(" "),
        dir
    );
    let ret = Command::new(program).current_dir(dir).args(args).status();

    match ret.map(|status| (status.success(), status.code())) {
        Ok((true, _)) => (),
        Ok((false, Some(c))) => panic!("Command failed with error code {}", c),
        Ok((false, None)) => panic!("Command got killed"),
        Err(e) => panic!("Command failed with error: {}", e),
    }
}

fn main() {
    if !Path::new("librocksdb-sys/rocksdb/AUTHORS").exists() {
        println!("cargo:rustc-cfg=NG_ROCKS_DB_NOT_FOUND");
        if std::env::var("DOCS_RS").is_ok() {
            println!("cargo:rustc-cfg=DOCS_RS");
        }
        return;
        //update_submodules();
    }
    let target = env::var("TARGET").unwrap();
    if target.contains("openbsd") {
        env::set_var("LIBCLANG_PATH", "/usr/local/llvm17/lib");
    } else if target.contains("windows") {
        env::set_var("LIBCLANG_PATH", "C:\\Program Files\\LLVM\\bin");
    }

    bindgen_rocksdb();

    if !try_to_find_and_link_lib("ROCKSDB") {
        println!("cargo:rerun-if-changed=librocksdb-sys/");
        fail_on_empty_directory("librocksdb-sys/rocksdb");
        build_rocksdb();
    } else {
        let target = env::var("TARGET").unwrap();
        // according to https://github.com/alexcrichton/cc-rs/blob/master/src/lib.rs#L2189
        if target.contains("apple") || target.contains("freebsd") || target.contains("openbsd") {
            println!("cargo:rustc-link-lib=dylib=c++");
        } else if target.contains("linux") {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
    }
    if cfg!(feature = "snappy") && !try_to_find_and_link_lib("SNAPPY") {
        println!("cargo:rerun-if-changed=snappy/");
        fail_on_empty_directory("snappy");
        build_snappy();
    }

    // Allow dependent crates to locate the sources and output directory of
    // this crate. Notably, this allows a dependent crate to locate the RocksDB
    // sources and built archive artifacts provided by this crate.
    println!(
        "cargo:cargo_manifest_dir={}",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:out_dir={}", env::var("OUT_DIR").unwrap());
}
