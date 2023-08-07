#include "../rocksdb/include/rocksdb/version.h"

#include "c.h"

static char* CopyString(const std::string& str) {
  char* result = reinterpret_cast<char*>(malloc(sizeof(char) * str.size()));
  memcpy(result, str.data(), sizeof(char) * str.size());
  return result;
}

extern "C" {

char* rocksdb_version() {
  auto name = ROCKSDB_NAMESPACE::GetRocksVersionAsString(true);
  return CopyString(name);
}

}
