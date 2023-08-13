include ../../../make_config.mk

PLATFORM_LDFLAGS += -lrocksdb -lcrypto -L../../.. -L../../../../rust-rocksdb/target/debug/build/openssl-sys-019f70ebcbe84526/out/openssl-build/install/lib/	
.PHONY: clean

all: ippcp_example

ippcp_example: ippcp_example.cc
	$(CXX) $(CXXFLAGS) $@.cc -o$@ -I../../../include -O2 $(PLATFORM_LDFLAGS) $(PLATFORM_CXXFLAGS) -I../include

clean:
	rm -rf ./ippcp_example
