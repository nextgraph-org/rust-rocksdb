/*
 * Copyright (c) 2022-2023 Niko Bonnieure, Par le Peuple, NextGraph.org developers
 * All rights reserved.
 * Licensed under the Apache License, Version 2.0
 * <LICENSE-APACHE2 or http://www.apache.org/licenses/LICENSE-2.0>
 * or the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
 * at your option. All files in the project carrying such
 * notice may not be copied, modified, or distributed except
 * according to those terms.
//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
 */

#ifndef ROCKSDB_LITE

#include "openssl_provider.h"

#include <rocksdb/utilities/object_registry.h>
#include "rocksdb/utilities/customizable_util.h"
#include <memory>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdint.h> 
#include <limits.h>
#include "portable_endian.h"

#endif

namespace ROCKSDB_NAMESPACE {

#ifndef ROCKSDB_LITE

static void RegisterEncryptionAES() {
  static std::once_flag once;
  std::call_once(once, [&]() {

    ERR_load_crypto_strings();

    ObjectLibrary::Default()->AddFactory<EncryptionProvider>(
        OpensslProvider::kName(),
        [](const std::string& /* uri */, std::unique_ptr<EncryptionProvider>* f,
           std::string* /* errmsg */) {
          *f = OpensslProvider::CreateProvider();
          return f->get();
        });

  });
}

Status EncryptionProvider::CreateFromString(
    const ConfigOptions& config_options, const std::string& value,
    std::shared_ptr<EncryptionProvider>* result) {
  RegisterEncryptionAES();
  return LoadSharedObject<EncryptionProvider>(config_options, value, result);
}

// extern "C" FactoryFunc<EncryptionProvider> ippcp_reg;

// FactoryFunc<EncryptionProvider> ippcp_reg =
//     ObjectLibrary::Default()->AddFactory<EncryptionProvider>(
//         OpensslProvider::kName(),
//         [](const std::string& /* uri */, std::unique_ptr<EncryptionProvider>* f,
//            std::string* /* errmsg */) {
//           *f = OpensslProvider::CreateProvider();
//           return f->get();
//         });

// OpensslCipherStream implements BlockAccessCipherStream using AES block
// cipher and a CTR mode of operation.
//
class OpensslCipherStream : public BlockAccessCipherStream {
 public:
  static constexpr size_t kBlockSize = 16;    // in bytes
  //static constexpr size_t kCounterLen = 64;  // in bits

  OpensslCipherStream(const EVP_CIPHER *aes_cipher, const unsigned char* key, const char* init_vector);

  ~OpensslCipherStream();

  virtual Status Encrypt(uint64_t fileOffset, char* data,
                         size_t dataSize) override;
  virtual Status Decrypt(uint64_t fileOffset, char* data,
                         size_t dataSize) override;
  virtual size_t BlockSize() override { return kBlockSize; }

 protected:
  // These functions are not needed and will never be called!
  virtual void AllocateScratch(std::string&) override {}
  virtual Status EncryptBlock(uint64_t, char*, char*) override {
    return Status::NotSupported("Operation not supported.");
  }
  virtual Status DecryptBlock(uint64_t, char*, char*) override {
    return Status::NotSupported("Operation not supported.");
  }

 private:
  const EVP_CIPHER *aes_cipher_;
  const unsigned char* key_;
  char init_vector_[kBlockSize];

  Status handleErrors(const char * str);
};

OpensslCipherStream::OpensslCipherStream(const EVP_CIPHER *aes_cipher,
                                     const unsigned char* key,
                                     const char* init_vector)
    : aes_cipher_(aes_cipher), key_(key) {
    memcpy(init_vector_,init_vector,kBlockSize);
    //ctx_ = EVP_CIPHER_CTX_new();
}

OpensslCipherStream::~OpensslCipherStream() {
  //EVP_CIPHER_free(aes_cipher_);
  //if (ctx_ != nullptr) EVP_CIPHER_CTX_free(ctx_);
}

Status OpensslCipherStream::handleErrors(const char * str) {
  # ifndef OPENSSL_NO_STDIO
  ERR_print_errors_fp(stderr);
  # endif

  // if (ctx_ != nullptr) { 
  //   EVP_CIPHER_CTX_free(ctx_);
  //   ctx_ = nullptr;
  // }
  return Status::Aborted(str);
}

// #include <inttypes.h>
// void printb(const char * name, const char * buffer, size_t n) {
//   int nn = static_cast<int>(n);
//   printf("%s (%d)\n",name,nn);
//   for(int i = 0; i<nn; i++)
//      printf("%x ", static_cast<unsigned char>(buffer[i]));

//   printf("\n");
// }

Status OpensslCipherStream::Encrypt(uint64_t fileOffset, char* data,
                                  size_t dataSize) {
  if (dataSize == 0) return Status::OK();

  const char * err_str = nullptr;

  EVP_CIPHER_CTX* ctx_ = EVP_CIPHER_CTX_new();
  // if ( 1 != EVP_CIPHER_CTX_reset(ctx_)) { err_str="Failed to reset context."; goto error; }

  size_t index = fileOffset / kBlockSize;
  size_t offset = fileOffset % kBlockSize;

  // printf("\nfileOffset %" PRIu64 " INDEX %zu OFFSET %zu\n",fileOffset,index,offset);
  // printb("data",data,dataSize);
  
  unsigned char ctr_block[kBlockSize];

  uint64_t init_vector_lower_part;
  memcpy(&init_vector_lower_part, init_vector_+8, sizeof init_vector_lower_part);
  // printb("right part of IV",init_vector_+8,8);

  uint64_t init_vector_lower_part_h = be64toh(init_vector_lower_part);
  // printf("right part of IV as host %" PRIu64 "\n",init_vector_lower_part_h);

  memcpy(ctr_block, init_vector_, 8);
  ctr_block[7] &= 254; // we zero the right-most bit, for the eventual remainder
  // printb("left part of IV",(const char*)ctr_block,8);

  if (index > ULLONG_MAX - init_vector_lower_part_h) {
    // we have an overflow already now, even before dataSize is added
    // we set the remainder bit
    // use |= 1 to set the right-most last bit to 1 (the remainder)
    ctr_block[7] |= 1;
    // printf("will overflow\n");
    // printb("new left part of IV",(const char*)ctr_block,8);
  }

  uint64_t be_counter = htobe64(index + init_vector_lower_part_h);
  // printf("counter as host %" PRIu64 "\n",index + init_vector_lower_part_h);
  // printf("counter as BE %" PRIu64 "\n",be_counter);
  char* ptr_counter = (char*)&be_counter;
  for (size_t i = 8; i < 16; ++i)
    ctr_block[i] = ptr_counter[i-8];

  // printb("right part of IV",(const char*)ctr_block+8,8);

  int len;

  if( 1 != EVP_EncryptInit_ex(ctx_, aes_cipher_, NULL, key_, ctr_block)) {err_str="Failed to init cipher."; goto error;}
  EVP_CIPHER_CTX_set_padding(ctx_, 0);

  if (offset == 0) {
    unsigned char *out = (unsigned char*)malloc(dataSize);
    if( 1 != EVP_EncryptUpdate(ctx_, out, &len, reinterpret_cast<const unsigned char *>(data), static_cast<int>(dataSize))) {err_str="Failed to encrypt."; goto error;}
    memcpy(data, out, dataSize);
    //EVP_EncryptFinal_ex(ctx_, reinterpret_cast<unsigned char *>(data) + len, &len);

  } else {
    
    unsigned char zero_block[kBlockSize]{0};
    unsigned char zero_block_out[kBlockSize]{0};
    if( 1 != EVP_EncryptUpdate(ctx_, zero_block_out, &len, zero_block, static_cast<int>(kBlockSize))) {err_str="Failed to encrypt zero block."; goto error;}
    //unsigned char * end = reinterpret_cast<unsigned char *>(zero_block) + len;

    size_t n = std::min(kBlockSize - offset, dataSize);
    for (size_t i = 0; i < n; ++i) data[i] ^= zero_block_out[offset + i];
    //memset(zero_block, 0, kBlockSize);

    n = kBlockSize - offset;
    if (dataSize > n) {
      char* ptr = (char*)(data + n);
      unsigned char *out = (unsigned char*)malloc(dataSize - n);
      if( 1 != EVP_EncryptUpdate(ctx_, out, &len, reinterpret_cast<const unsigned char *>(ptr), static_cast<int>(dataSize - n))) {err_str="Failed to encrypt remaining."; goto error;}
      memcpy(ptr, out, dataSize - n);
      //end = reinterpret_cast<unsigned char *>(ptr) + len;
    }

    //EVP_EncryptFinal_ex(ctx_, end, &len);
  }

  if (ctx_ != nullptr) EVP_CIPHER_CTX_free(ctx_);

  return Status::OK();

  error:
    if (ctx_ != nullptr) EVP_CIPHER_CTX_free(ctx_);
    ERR_print_errors_fp(stderr);
    if (err_str != nullptr) return Status::Aborted(err_str);
    else return Status::Aborted("unknown error");

}

Status OpensslCipherStream::Decrypt(uint64_t fileOffset, char* data,
                                  size_t dataSize) {
  // Decryption is implemented as encryption in CTR mode of operation
  return Encrypt(fileOffset, data, dataSize);
}

std::unique_ptr<EncryptionProvider> OpensslProvider::CreateProvider() {
  return std::unique_ptr<EncryptionProvider>(new OpensslProvider);
}

Status OpensslProvider::handleErrors (const char * str) const {
  # ifndef OPENSSL_NO_STDIO
  ERR_print_errors_fp(stderr);
  # endif
  return Status::Aborted(str);
}

Status OpensslProvider::AddCipher(const std::string& /*descriptor*/,
                                const char* cipher, size_t len,
                                bool /*for_write*/) {
  // We currently don't support more than one encryption key
  if (aes_cipher_ != nullptr) {
    return Status::InvalidArgument("Multiple encryption keys not supported.");
  }

  key_ = reinterpret_cast<const unsigned char *>(cipher);

  if (len == 16) {  aes_cipher_ = EVP_aes_128_ctr(); }
  else if (len == 24) { aes_cipher_ = EVP_aes_192_ctr(); }
  else if (len == 32) { aes_cipher_ = EVP_aes_256_ctr(); }
  else return Status::InvalidArgument("Invalid key size in provider.");

  //if( 1 != EVP_CIPHER_up_ref(aes_cipher_)) return handleErrors("Failed to create provider.");

  return Status::OK();
}

Status OpensslProvider::CreateNewPrefix(const std::string& /*fname*/,
                                      char* prefix, size_t prefixLength) const {
  if (1 != RAND_bytes(reinterpret_cast<unsigned char *>(prefix), static_cast<int>(OpensslCipherStream::kBlockSize)) ){
    return handleErrors("Failed to get random numbers.");//Status::Aborted(ERR_reason_error_string(ERR_get_error()));
  }
  //if( 1 != EVP_CIPHER_up_ref(aes_cipher_)) return handleErrors("Failed to create OpensslCipherStream.");

  // printb("new prefix",prefix,32);

  OpensslCipherStream cs(aes_cipher_, key_, prefix);
  Status s = cs.Encrypt(0, prefix + OpensslCipherStream::kBlockSize,
                    prefixLength - OpensslCipherStream::kBlockSize);
  // printb("encoded prefix",prefix + OpensslCipherStream::kBlockSize,16);
  return s;
}

Status OpensslProvider::CreateCipherStream(
    const std::string& /*fname*/, const EnvOptions& /*options*/, Slice& prefix,
    std::unique_ptr<BlockAccessCipherStream>* result) {
  assert(result != nullptr);
  assert(prefix.size() >= OpensslCipherStream::kBlockSize);
  //if( 1 != EVP_CIPHER_up_ref(aes_cipher_)) return handleErrors("Failed to create OpensslCipherStream.");
  result->reset(new OpensslCipherStream(aes_cipher_, key_, prefix.data()));
  Status status = (*result)->Decrypt(
      0, (char*)prefix.data() + OpensslCipherStream::kBlockSize,
      prefix.size() - OpensslCipherStream::kBlockSize);
  // printb("decoded prefix",(char*)prefix.data() + OpensslCipherStream::kBlockSize,16);
  return status;
}

OpensslProvider::~OpensslProvider() {
  ////EVP_CIPHER_free(aes_cipher_);
  //FIXME: zero the key
  //memset(key_, 0, key_len_);
  (void)(key_len_);
}

#endif  // ROCKSDB_LITE

}  // namespace ROCKSDB_NAMESPACE
