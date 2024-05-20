# ng-rocksdb

This is a fork of https://github.com/rust-rocksdb/rust-rocksdb that also includes a subtree of a fork of https://github.com/facebook/rocksdb for the needs of NextGraph.org project.

## Requirements

- Clang and LLVM

### On OpenBSD

```
pkg_add llvm
```

### On macos

```
port install clang
```

### On windows

download from [here](https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.0/LLVM-16.0.0-win64.exe)

## Contributing

Feedback and pull requests welcome! If a particular feature of RocksDB is
important to you, please let me know by opening an issue, and I'll
prioritize it.

## Compression Support

By default, support for the [Snappy](https://github.com/google/snappy),
[LZ4](https://github.com/lz4/lz4), [Zstd](https://github.com/facebook/zstd),
[Zlib](https://zlib.net), and [Bzip2](http://www.bzip.org) compression
is enabled through crate features. If support for all of these compression
algorithms is not needed, default features can be disabled and specific
compression algorithms can be enabled. For example, to enable only LZ4
compression support, make these changes to your Cargo.toml:

## Multithreaded ColumnFamily alternation

The underlying RocksDB does allow column families to be created and dropped
from multiple threads concurrently. But this crate doesn't allow it by default
for compatibility. If you need to modify column families concurrently, enable
crate feature called `multi-threaded-cf`, which makes this binding's
data structures to use RwLock by default. Alternatively, you can directly create
`DBWithThreadMode<MultiThreaded>` without enabling the crate feature.
