//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#if !defined(ROCKSDB_LITE)

#include <openssl/evp.h>
#include <rocksdb/env_encryption.h>

#include <string>

namespace ROCKSDB_NAMESPACE {


// This encryption provider uses AES block cipher and a CTR mode of operation
// with a cryptographically secure IV that is randomly generated.
//
// Note: a prefix size of 4096 (4K) is chosen for optimal performance.
//
class OpensslProvider : public EncryptionProvider {
 public:
  static constexpr size_t kPrefixSize = 4096;

  static std::unique_ptr<EncryptionProvider> CreateProvider();

  static const char* kName() { return "ippcp"; }

  virtual const char* Name() const override { return kName(); }

  virtual size_t GetPrefixLength() const override { return kPrefixSize; }

  virtual Status AddCipher(const std::string& /*descriptor*/,
                           const char* /*cipher*/, size_t /*len*/,
                           bool /*for_write*/) override;

  virtual Status CreateNewPrefix(const std::string& fname, char* prefix,
                                 size_t prefixLength) const override;

  virtual Status CreateCipherStream(
      const std::string& fname, const EnvOptions& options, Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result) override;

  virtual ~OpensslProvider();

 private:
  const EVP_CIPHER *aes_cipher_;
  //const unsigned char *key_;
  unsigned char key_[32];
  size_t key_len_;
  OpensslProvider()
      : aes_cipher_(nullptr), key_len_(0) {}
  OpensslProvider(const OpensslProvider&) = delete;
  OpensslProvider& operator=(const OpensslProvider&) = delete;
  Status handleErrors (const char * str) const;
};

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE)
