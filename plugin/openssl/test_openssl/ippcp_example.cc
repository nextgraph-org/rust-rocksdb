//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  Copyright (c) 2020 Intel Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <rocksdb/db.h>
#include <rocksdb/env_encryption.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/utilities/options_util.h>
#include <rocksdb/utilities/object_registry.h>

#include <string>

#include "../openssl_provider.h"

using namespace ROCKSDB_NAMESPACE;

std::string kDBPath = "/tmp/oss_aes_example";

int main() {

  std::unique_ptr<EncryptionProvider> provider = OpensslProvider::CreateProvider();
  provider->AddCipher("", "a6d2ae2816157e2b3c4fcf098815f7xb", 32, false);
  char prefixb[4096];
  Slice ps = Slice(prefixb, 4096);
  provider->CreateNewPrefix("",prefixb,4096);
  Status s;
    // const EnvOptions envoptions;
    // std::unique_ptr<BlockAccessCipherStream> s;
    // provider->CreateCipherStream("",envoptions,ps,&s);

    // size_t prefixLen = 16; // minimum size of prefix is 16(blockSize)
    // uint8_t ctr[] = {0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // Slice prefix((char *)ctr, prefixLen);

    // std::unique_ptr<BlockAccessCipherStream> stream;
    // // creating cipher stream object to perform encryption and decryption
    // Status sta = provider->CreateCipherStream("", envoptions, prefix, &stream);
    // assert(sta.ok());

    // std::string input1, input2, input3, plainTxt;
    // uint64_t offset = 0; // offset where from we need to perform encryption/decryption
    // plainTxt = "";
    // input1.assign("1 input for CounterBlk hellooo0 ");
    // input2.assign("2 input for CounterBlk hellooo0 ");
    // input3.assign("3 input for CounterBlk  helloo0 ");
    // // concatenate the strings and encrypt them
    // plainTxt = input1 + input2 + input3;
    // sta = stream->Encrypt(offset, (char *)plainTxt.c_str(), plainTxt.length()); // does in place encryption so plainTxt will be encrypted now
    // sta = stream->Decrypt(offset, (char *)plainTxt.c_str(), plainTxt.length()); // in .place decryption
    // assert(input1 + input2 + input3 == plainTxt);





    // // creating prefix which sets the 128 initVector data memmber
    // size_t prefixLen = 16; // minimum size of prefix is 16
    // // setting prefix/counter to all ff's to check the overflow
    // uint8_t ctr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // Slice prefix((char *)ctr, prefixLen);
    // // creating cipher stream object to perform encryption and decryption
    // std::unique_ptr<BlockAccessCipherStream> stream;
    // const EnvOptions options;
    // s = provider->CreateCipherStream("", options, prefix, &stream);
    // assert(s.ok());

    // // creating string each of 16 byte(blocksize) for encryption
    // std::string str1, str2, str3;
    // str1.assign("1111111111111111");
    // str2.assign("2222222222222222");
    // str3.assign("3333333333333333");

    // std::string encryptedString = "";
    // encryptedString += str1;
    // encryptedString += str2;
    // encryptedString += str3;
    // // encrypted all the strings in one go.Here ipp lib will create counter block for 2nd and 3rd string block
    // s = stream->Encrypt(0, (char *)encryptedString.c_str(), encryptedString.length());
    // std::string cipherTxt = encryptedString.substr(str1.length());
    // // decrypt the encrypted string from str2 onwards i.e from block 2 onwards
    // s = stream->Decrypt(str1.length(), (char *)cipherTxt.c_str(), cipherTxt.length());
    // // the decrypted string should match the str2 + str3
    // assert((str2 + str3) == cipherTxt);
    // assert(s.ok());




    // size_t prefixLen = provider->GetPrefixLength();
    // assert(prefixLen > 0);
    // char *buf = (char *)malloc(prefixLen);
    // assert(buf != nullptr);
    // std::unique_ptr<BlockAccessCipherStream> stream;
    // const EnvOptions options;
    // s = provider->CreateNewPrefix("", buf, prefixLen);
    // assert(s.ok());
    // Slice prefix(buf, prefixLen);

    // s = provider->CreateCipherStream("", options, prefix, &stream);
    // assert(s.ok());

    // std::string input, plainTxt;
    // uint64_t offset = prefixLen;
    // input.assign("test ippcp crypto");
    // plainTxt = input;                                                   //  input becomes cipher txt in below API.
    // s = stream->Encrypt(offset, (char *)input.c_str(), input.length()); // does in place encryption
    // assert(s.ok());
    // s = stream->Decrypt(offset, (char *)input.c_str(), input.length());
    // assert(plainTxt == input);
    // free(buf);

    // size_t prefixLen = provider->GetPrefixLength();
    // char *buf = (char *)malloc(prefixLen);
    // assert(buf != nullptr);
    // s = provider->CreateNewPrefix("", buf, prefixLen);
    // assert(s.ok());
    // Slice prefix(buf, prefixLen);

    // std::unique_ptr<BlockAccessCipherStream> stream;
    // const EnvOptions options;
    // s = provider->CreateCipherStream("", options, prefix, &stream);
    // assert(s.ok());

    // std::string input1, plainTxt, cipherTxt;
    // uint64_t offset = prefixLen;

    // input1.assign("1 input for encryption hellooo0 ");
    // plainTxt = input1;
    // s = stream->Encrypt(offset, (char *)input1.c_str(), input1.length()); // does in place encryption
    // assert(s.ok());
    // cipherTxt = input1;
    // offset += input1.length();

    // std::string input2;
    // input2.assign("2 input for encryption hellooo0 ");
    // plainTxt += input2;
    // s = stream->Encrypt(offset, (char *)input2.c_str(), input2.length()); // does in place encryption
    // assert(s.ok());
    // cipherTxt += input2;
    // offset += input2.length();

    // std::string input3;
    // input3.assign("3 input for encryption  helloo0 ");
    // plainTxt += input3;
    // s = stream->Encrypt(offset, (char *)input3.c_str(), input3.length()); // does in place encryption
    // assert(s.ok());
    // cipherTxt += input3;
    // // decrypt the all the input string in one go.
    // s = stream->Decrypt(prefixLen, (char *)cipherTxt.c_str(), cipherTxt.length());

    // assert(plainTxt == cipherTxt);
    // free(buf);




    // // creating prefix which sets the 128 initVector data memmber
    // size_t prefixLen = 16; // minimum size of prefix is 16
    // // setting prefix/counter to all ff's to check the overflow
    // uint8_t ctr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // Slice prefix((char *)ctr, prefixLen);
    // // creating cipher stream object to perform encryption and decryption
    // std::unique_ptr<BlockAccessCipherStream> stream;
    // const EnvOptions options;
    // s = provider->CreateCipherStream("", options, prefix, &stream);
    // assert(s.ok());

    // // creating string each of 16 byte(blocksize) for encryption
    // std::string str1, str2, str3;
    // str1.assign("1111111111111111");
    // str2.assign("2222222222222222");
    // str3.assign("3333333333333333");

    // std::string encryptedString = "";
    // encryptedString += str1;
    // encryptedString += str2;
    // encryptedString += str3;
    // // encrypted all the strings in one go.Here ipp lib will create counter block for 2nd and 3rd string block
    // s = stream->Encrypt(0, (char *)encryptedString.c_str(), encryptedString.length());
    // std::string cipherTxt = encryptedString.substr(str1.length());
    // // decrypt the encrypted string from str2 onwards i.e from block 2 onwards
    // s = stream->Decrypt(str1.length(), (char *)cipherTxt.c_str(), cipherTxt.length());
    // // the decrypted string should match the str2 + str3
    // assert((str2 + str3) == cipherTxt);
    // assert(s.ok());

  /********************/

  DB* db;
  Options dboptions;
  dboptions.create_if_missing = true;

  std::shared_ptr<EncryptionProvider> sprovider;
  Status status = EncryptionProvider::CreateFromString(
      ConfigOptions(), "ippcp", &sprovider);
  assert(status.ok());

  status =
      sprovider->AddCipher("", "a6d2ae2816157e2b3c4fcf098815f7xb", 32, false);
  assert(status.ok());

  dboptions.env = NewEncryptedEnv(Env::Default(), sprovider);

  status = DB::Open(dboptions, kDBPath, &db);
  assert(status.ok());

  setbuf(stdout, NULL);
  printf("writing 1M records...");
  WriteOptions w_opts;
  for (int i = 0; i < 1000000; ++i) {
    status = db->Put(w_opts, std::to_string(i), std::to_string(i * i));
    assert(status.ok());
  }
  db->Flush(FlushOptions());
  printf("done.\n");

  printf("reading 1M records...");
  std::string value;
  ReadOptions r_opts;
  for (int i = 0; i < 1000000; ++i) {
    status = db->Get(r_opts, std::to_string(i), &value);
    assert(status.ok());
    assert(value == std::to_string(i * i));
  }
  printf("done.\n");

  // Close database
  status = db->Close();
  assert(status.ok());
  status = DestroyDB(kDBPath, dboptions);
  assert(status.ok());

  return 0;
}
