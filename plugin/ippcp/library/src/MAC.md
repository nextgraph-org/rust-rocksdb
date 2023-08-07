## How to build on macOS

- download Intel CPP Classic compiler from [here](https://www.intel.com/content/www/us/en/developer/articles/tool/oneapi-standalone-components.html#dpcpp-cpp)
- choose offline installer m_cpp-compiler-classic_p_2023.2.0.48999_offline.dmg
- `wget https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/macosx/nasm-2.16.01-macosx.zip`
- extract zip file
- `wget https://www.openssl.org/source/openssl-3.1.2.tar.gz`
- in `openssl-3.1.2` extracted folder :

```
./Configure
make
```

- in this `src` folder: (or `git clone https://github.com/intel/ipp-crypto` for newer)

```
source  /opt/intel/oneapi/compiler/2023.2.0/env/vars.sh intel64
export ASM_NASM=/[your_path_here]/nasm-2.16.01/nasm
CC=icc CXX=icpc cmake CMakeLists.txt -B_build -DARCH=intel64 -DOPENSSL_INCLUDE_DIR=/[your_path_here]/openssl-3.1.2/include -DOPENSSL_LIBRARIES=/[your_path_here]/openssl-3.1.2 -DOPENSSL_ROOT_DIR=/[your_path_here]/openssl-3.1.2
cd _build
make ippcp_s
```
