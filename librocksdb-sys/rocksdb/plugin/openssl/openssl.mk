openssl_SOURCES = openssl_provider.cc
openssl_HEADERS = openssl_provider.h
openssl_LDFLAGS = -lcrypto
openssl_CXXFLAGS = -Iplugin/openssl/include -isystemplgun/openssl/include
