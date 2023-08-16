include ../../../make_config.mk

PLATFORM_LDFLAGS += -lrocksdb -lippcp -L../../.. -L../library/macos/lib
.PHONY: clean

all: ippcp_example

ippcp_example: ippcp_example.cc
	$(CXX) $(CXXFLAGS) $@.cc -o$@ -I../../../include -O2 $(PLATFORM_LDFLAGS) $(PLATFORM_CXXFLAGS) -I../library/include

clean:
	rm -rf ./ippcp_example
