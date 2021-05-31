/* 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <iostream>
#include <stdio.h>

#include "gtest/gtest.h"

#include "shim/hash.h"

using namespace std;

/*
 * This test suite is not aimed at being a comprehensive test suite for hash
 * functions. Instead, we assume that the underlying library does pass the
 * appropriate tests (e.g., NIST's), and include a "cannary" kind of test here:
 * i.e., we just verify one test sample per supported algorithm, and assume that
 * if the result is correct, then the shim layer is correct. Note: this may not
 * be the case, and it is just a compromise. (E.g., the shim layer does not
 * support hashing 0-byte arrays, while the test vectors from NIST, do.)
 */
namespace hash {

  const byte_t SHA1_VEC1_PRE[] = { 0x36 };

  const byte_t SHA1_VEC1_IMG[] = {
    0xc1, 0xdf, 0xd9, 0x6e,
    0xea, 0x8c, 0xc2, 0xb6,
    0x27, 0x85, 0x27, 0x5b,
    0xca, 0x38, 0xac, 0x26,
    0x12, 0x56, 0xe2, 0x78
  };

  const byte_t BLAKE2_VEC1_PRE[] = {
    0x61, 0x62, 0x63
  };

  const byte_t BLAKE2_VEC1_IMG[] = {
    0x50, 0x8C, 0x5E, 0x8C,
    0x32, 0x7C, 0x14, 0xE2,
    0xE1, 0xA7, 0x2B, 0xA3,
    0x4E, 0xEB, 0x45, 0x2F,
    0x37, 0x45, 0x8B, 0x20,
    0x9E, 0xD6, 0x3A, 0x29,
    0x4D, 0x99, 0x9B, 0x4C,
    0x86, 0x67, 0x59, 0x82
  };
  
  // The fixture for testing operations with big numbers.
  class HashTest : public ::testing::Test {
    
  protected:
    
    HashTest() { }
    
    ~HashTest() override { }
    
    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:
    
    void SetUp() override {
      // Code here will be called immediately after the constructor (right
      // before each test).
    }
    
    void TearDown() override {
      // Code here will be called immediately after each test (right
      // before the destructor).
    }
    
  };

  TEST_F(HashTest, sha1GetVec1) {
    
    hash_t *h;
    byte_t str[100];
    int rc;

    memset(str, 0, 100);
    memcpy(str, SHA1_VEC1_PRE, 1);
    
    h = hash_get(HASH_SHA1, str, 1);
    EXPECT_NE(h, nullptr);
    
    rc = memcmp(h->hash, SHA1_VEC1_IMG, HASH_SHA1_LENGTH);
    EXPECT_EQ(rc, 0);
    
    rc = hash_free(h);
    EXPECT_EQ(rc, IOK);
    
  }
  
  TEST_F(HashTest, sha1InitUpdateFinalizeVec1) {
    
    hash_t *h;
    byte_t str[100];    
    int rc;

    memset(str, 0, 100);
    memcpy(str, SHA1_VEC1_PRE, 1);    
    
    h = hash_init(HASH_SHA1);
    EXPECT_NE(h, nullptr);
    
    rc = hash_update(h, str, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = hash_finalize(h);
    EXPECT_EQ(rc, IOK);
    
    rc = memcmp(h->hash, SHA1_VEC1_IMG, HASH_SHA1_LENGTH);
    EXPECT_EQ(rc, 0);
    
    rc = hash_free(h);
    EXPECT_EQ(rc, IOK);
    
  }

  TEST_F(HashTest, blake2GetVec1) {
    
    hash_t *h;
    byte_t str[100];
    int rc;

    memset(str, 0, 100);
    memcpy(str, BLAKE2_VEC1_PRE, 3);
    
    h = hash_get(HASH_BLAKE2, str, 3);
    EXPECT_NE(h, nullptr);
    
    rc = memcmp(h->hash, BLAKE2_VEC1_IMG, HASH_BLAKE2_LENGTH);
    EXPECT_EQ(rc, 0);
    
    rc = hash_free(h);
    EXPECT_EQ(rc, IOK);
    
  }
  
  TEST_F(HashTest, blake2InitUpdateFinalizeVec1) {
    
    hash_t *h;
    byte_t str[100];    
    int rc;

    memset(str, 0, 100);
    memcpy(str, BLAKE2_VEC1_PRE, 3);    
    
    h = hash_init(HASH_BLAKE2);
    EXPECT_NE(h, nullptr);
    
    rc = hash_update(h, str, 3);
    EXPECT_EQ(rc, IOK);
    
    rc = hash_finalize(h);
    EXPECT_EQ(rc, IOK);
    
    rc = memcmp(h->hash, BLAKE2_VEC1_IMG, HASH_BLAKE2_LENGTH);
    EXPECT_EQ(rc, 0);
    
    rc = hash_free(h);
    EXPECT_EQ(rc, IOK);
    
  }  
  
}  // namespace hash

