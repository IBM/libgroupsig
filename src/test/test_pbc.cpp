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

#include "sysenv.h"
#include "shim/pbc_ext.h"

using namespace std;

/*
 * Note: These tests do not evaluate the precission (and not even the 
 * correctness) of operations on very large numbers. They rather test
 * that the shim'ed libraries implement the required functionality.
 * I.e., correctness & precission is assumed (so, be careful on what
 * libraries you use as engine for PBC...)
 */
namespace pbcext {

  // The fixture for testing operations with big numbers.
  class PBCTest : public ::testing::Test {
  protected:

    PBCTest() {
      pbcext_init(BLS12_381);
    }
    
    ~PBCTest() override {
    }

    
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

    // Class members declared here can be used by all tests in the test suite
  };

  /******** Fp ********/

  TEST_F(PBCTest, InitFpFree) {

    pbcext_element_Fp_t *e;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitFpClearFree) {

    pbcext_element_Fp_t *e;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_Fp_clear(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_is0(e);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitFpRandomSetCmpFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFpRandomSetAddFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_clear(e2);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFpRandomSetSubCmpFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_sub(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFpRandomSetNegCmpFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_neg(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }
  
  TEST_F(PBCTest, InitFpRandomSetInvCmpFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_inv(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_mul(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_is1(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFpRandomSetDivCmpFree) {

    pbcext_element_Fp_t *e, *e2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_div(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_is1(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFpRandomSizeFree) {

    pbcext_element_Fp_t *e;
    uint64_t size;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_byte_size(&size);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(size, 0);
    
    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

  }  
  
  TEST_F(PBCTest, InitFpRandomExportImportFree) {

    pbcext_element_Fp_t *e, *e2;
    unsigned char *dst;
    uint64_t len;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_element_Fp_to_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_Fp_from_bytes(e2, dst, len);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitFpRandomExportImportB64Free) {

    pbcext_element_Fp_t *e, *e2;
    char *dst;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    dst = pbcext_element_Fp_to_b64(e);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_Fp_from_b64(e2, dst);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fp_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitFpRandomDumpExportImportFree) {

    pbcext_element_Fp_t *e, *e2;
    unsigned char *dst;
    uint64_t len, len2;
    int rc;

    e = pbcext_element_Fp_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fp_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_dump_element_Fp_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fp_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_get_element_Fp_bytes(e2, &len2, dst);
    EXPECT_NE(rc, IERROR);
    EXPECT_EQ(len, len2);

    rc = pbcext_element_Fp_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fp_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fp_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);

  }

  /******** Fr ********/

  TEST_F(PBCTest, InitFrFree) {

    pbcext_element_Fr_t *e;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitFrClearFree) {

    pbcext_element_Fr_t *e;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_Fr_clear(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_is0(e);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitFrRandomSetCmpFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFrRandomSetAddFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_clear(e2);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFrRandomSetSubCmpFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_sub(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFrRandomSetNegCmpFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_neg(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }
  
  TEST_F(PBCTest, InitFrRandomSetInvCmpFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_inv(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_mul(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_is1(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFrRandomSetDivCmpFree) {

    pbcext_element_Fr_t *e, *e2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_div(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_is1(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitFrRandomSizeFree) {

    pbcext_element_Fr_t *e;
    uint64_t size;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_byte_size(&size);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(size, 0);
    
    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

  }  
  
  TEST_F(PBCTest, InitFrRandomExportImportFree) {

    pbcext_element_Fr_t *e, *e2;
    unsigned char *dst;
    uint64_t len;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_element_Fr_to_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_Fr_from_bytes(e2, dst, len);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitFrRandomExportImportB64Free) {

    pbcext_element_Fr_t *e, *e2;
    char *dst;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    dst = pbcext_element_Fr_to_b64(e);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_Fr_from_b64(e2, dst);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_Fr_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitFrRandomDumpExportImportFree) {

    pbcext_element_Fr_t *e, *e2;
    unsigned char *dst;
    uint64_t len, len2;
    int rc;

    e = pbcext_element_Fr_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_Fr_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_dump_element_Fr_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_Fr_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_get_element_Fr_bytes(e2, &len2, dst);
    EXPECT_NE(rc, IERROR);
    EXPECT_EQ(len, len2);

    rc = pbcext_element_Fr_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_Fr_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);

  }

  /******** G1 ********/

  TEST_F(PBCTest, InitG1Free) {

    pbcext_element_G1_t *e;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitG1ClearFree) {

    pbcext_element_G1_t *e;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_G1_clear(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_is0(e);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitG1RandomSetCmpFree) {

    pbcext_element_G1_t *e, *e2;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG1RandomSetAddFree) {

    pbcext_element_G1_t *e, *e2;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_clear(e2);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG1RandomMulFree) {

    pbcext_element_G1_t *e;
    pbcext_element_Fr_t *r;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    r = pbcext_element_Fr_init();
    EXPECT_NE(r, nullptr);    
    
    rc = pbcext_element_Fr_random(r);
    EXPECT_NE(rc, IERROR);    

    rc = pbcext_element_G1_mul(e, e, r);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(r);
    EXPECT_EQ(rc, IOK);    

  }  

  TEST_F(PBCTest, InitG1RandomSetSubCmpFree) {

    pbcext_element_G1_t *e, *e2;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_sub(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG1RandomSetNegCmpFree) {

    pbcext_element_G1_t *e, *e2;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_neg(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);    

  }
  
  TEST_F(PBCTest, InitG1RandomSizeFree) {

    pbcext_element_G1_t *e;
    uint64_t size;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_byte_size(&size);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(size, 0);
    
    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

  }  
  
  TEST_F(PBCTest, InitG1RandomExportImportFree) {

    pbcext_element_G1_t *e, *e2;
    unsigned char *dst;
    uint64_t len;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_element_G1_to_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_G1_from_bytes(e2, dst, len);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitG1RandomExportImportB64Free) {

    pbcext_element_G1_t *e, *e2;
    char *dst;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    dst = pbcext_element_G1_to_b64(e);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_G1_from_b64(e2, dst);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G1_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitG1RandomDumpExportImportFree) {

    pbcext_element_G1_t *e, *e2;
    unsigned char *dst;
    uint64_t len, len2;
    int rc;

    e = pbcext_element_G1_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G1_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_dump_element_G1_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G1_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_get_element_G1_bytes(e2, &len2, dst);
    EXPECT_NE(rc, IERROR);
    EXPECT_EQ(len, len2);

    rc = pbcext_element_G1_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G1_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G1_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);

  }

  /******** G2 ********/

  TEST_F(PBCTest, InitG2Free) {

    pbcext_element_G2_t *e;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitG2ClearFree) {

    pbcext_element_G2_t *e;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_G2_clear(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_is0(e);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitG2RandomSetCmpFree) {

    pbcext_element_G2_t *e, *e2;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG2RandomSetAddFree) {

    pbcext_element_G2_t *e, *e2;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_clear(e2);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_cmp(e, e2);
    EXPECT_EQ(rc, 0);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG2RandomMulFree) {

    pbcext_element_G2_t *e;
    pbcext_element_Fr_t *r;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    r = pbcext_element_Fr_init();
    EXPECT_NE(r, nullptr);    
    
    rc = pbcext_element_Fr_random(r);
    EXPECT_NE(rc, IERROR);    

    rc = pbcext_element_G2_mul(e, e, r);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_Fr_free(r);
    EXPECT_EQ(rc, IOK);    

  }  

  TEST_F(PBCTest, InitG2RandomSetSubCmpFree) {

    pbcext_element_G2_t *e, *e2;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_set(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_sub(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);    

  }

  TEST_F(PBCTest, InitG2RandomSetNegCmpFree) {

    pbcext_element_G2_t *e, *e2;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);    
    
    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_neg(e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_add(e2, e2, e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_is0(e2);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);    

  }
  
  TEST_F(PBCTest, InitG2RandomSizeFree) {

    pbcext_element_G2_t *e;
    uint64_t size;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_byte_size(&size);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(size, 0);
    
    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

  }  
  
  TEST_F(PBCTest, InitG2RandomExportImportFree) {

    pbcext_element_G2_t *e, *e2;
    unsigned char *dst;
    uint64_t len;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_element_G2_to_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_G2_from_bytes(e2, dst, len);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitG2RandomExportImportB64Free) {

    pbcext_element_G2_t *e, *e2;
    char *dst;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    dst = pbcext_element_G2_to_b64(e);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_element_G2_from_b64(e2, dst);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_G2_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);    

  }

  TEST_F(PBCTest, InitG2RandomDumpExportImportFree) {

    pbcext_element_G2_t *e, *e2;
    unsigned char *dst;
    uint64_t len, len2;
    int rc;

    e = pbcext_element_G2_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_G2_random(e);
    EXPECT_NE(rc, IERROR);

    dst = nullptr;
    rc = pbcext_dump_element_G2_bytes(&dst, &len, e);
    EXPECT_NE(rc, IERROR);
    EXPECT_GT(len, 0);
    EXPECT_NE(dst, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);

    rc = pbcext_get_element_G2_bytes(e2, &len2, dst);
    EXPECT_NE(rc, IERROR);
    EXPECT_EQ(len, len2);

    rc = pbcext_element_G2_cmp(e, e2);
    EXPECT_EQ(rc, 0);
    
    rc = pbcext_element_G2_free(e);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);

    free(dst);

  }

  /******** GT ********/

  TEST_F(PBCTest, InitGTFree) {

    pbcext_element_GT_t *e;
    int rc;

    e = pbcext_element_GT_init();
    EXPECT_NE(e, nullptr);

    rc = pbcext_element_GT_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitGTClearFree) {

    pbcext_element_GT_t *e;
    int rc;

    e = pbcext_element_GT_init();
    EXPECT_NE(e, nullptr);
    
    rc = pbcext_element_GT_clear(e);
    EXPECT_NE(rc, IERROR);

    rc = pbcext_element_GT_is0(e);
    EXPECT_EQ(rc, 1);

    rc = pbcext_element_GT_free(e);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(PBCTest, InitGTPairFree) {

    pbcext_element_G1_t *e1;
    pbcext_element_G2_t *e2;
    pbcext_element_GT_t *e;
    int rc;

    e1 = pbcext_element_G1_init();
    EXPECT_NE(e1, nullptr);

    e2 = pbcext_element_G2_init();
    EXPECT_NE(e2, nullptr);

    e = pbcext_element_GT_init();
    EXPECT_NE(e, nullptr);    

    rc = pbcext_element_G1_random(e1);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_random(e2);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_pairing(e, e1, e2);
    EXPECT_EQ(rc, IOK);
    
    rc = pbcext_element_G1_free(e1);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_G2_free(e2);
    EXPECT_EQ(rc, IOK);

    rc = pbcext_element_GT_free(e);
    EXPECT_EQ(rc, IOK);    

  }

  // TEST_F(PBCTest, InitGTRandomSetInvCmpFree) {

  //   pbcext_element_GT_t *e, *e2;
  //   int rc;

  //   e = pbcext_element_GT_init();
  //   EXPECT_NE(e, nullptr);

  //   e2 = pbcext_element_GT_init();
  //   EXPECT_NE(e2, nullptr);    
    
  //   rc = pbcext_element_GT_random(e);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_inv(e2, e);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_diov(e2, e2, e);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_is1(e2);
  //   EXPECT_EQ(rc, 1);

  //   rc = pbcext_element_GT_free(e);
  //   EXPECT_EQ(rc, IOK);

  //   rc = pbcext_element_GT_free(e2);
  //   EXPECT_EQ(rc, IOK);    

  // }
  
  // TEST_F(PBCTest, InitGTRandomSizeFree) {

  //   pbcext_element_GT_t *e;
  //   uint64_t size;
  //   int rc;

  //   e = pbcext_element_GT_init();
  //   EXPECT_NE(e, nullptr);

  //   rc = pbcext_element_GT_random(e);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_byte_size(&size);
  //   EXPECT_NE(rc, IERROR);
  //   EXPECT_GT(size, 0);
    
  //   rc = pbcext_element_GT_free(e);
  //   EXPECT_EQ(rc, IOK);

  // }  
  
  // TEST_F(PBCTest, InitGTRandomExportImportFree) {

  //   pbcext_element_GT_t *e, *e2;
  //   unsigned char *dst;
  //   uint64_t len;
  //   int rc;

  //   e = pbcext_element_GT_init();
  //   EXPECT_NE(e, nullptr);

  //   rc = pbcext_element_GT_random(e);
  //   EXPECT_NE(rc, IERROR);

  //   dst = nullptr;
  //   rc = pbcext_element_GT_to_bytes(&dst, &len, e);
  //   EXPECT_NE(rc, IERROR);
  //   EXPECT_GT(len, 0);
  //   EXPECT_NE(dst, nullptr);

  //   e2 = pbcext_element_GT_init();
  //   EXPECT_NE(e2, nullptr);

  //   rc = pbcext_element_GT_from_bytes(e2, dst, len);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_cmp(e, e2);
  //   EXPECT_EQ(rc, 0);
    
  //   rc = pbcext_element_GT_free(e);
  //   EXPECT_EQ(rc, IOK);

  //   rc = pbcext_element_GT_free(e2);
  //   EXPECT_EQ(rc, IOK);

  //   free(dst);    

  // }

  // TEST_F(PBCTest, InitGTRandomExportImportB64Free) {

  //   pbcext_element_GT_t *e, *e2;
  //   char *dst;
  //   int rc;

  //   e = pbcext_element_GT_init();
  //   EXPECT_NE(e, nullptr);

  //   rc = pbcext_element_GT_random(e);
  //   EXPECT_NE(rc, IERROR);

  //   dst = nullptr;
  //   dst = pbcext_element_GT_to_b64(e);
  //   EXPECT_NE(dst, nullptr);

  //   e2 = pbcext_element_GT_init();
  //   EXPECT_NE(e2, nullptr);

  //   rc = pbcext_element_GT_from_b64(e2, dst);
  //   EXPECT_NE(rc, IERROR);

  //   rc = pbcext_element_GT_cmp(e, e2);
  //   EXPECT_EQ(rc, 0);
    
  //   rc = pbcext_element_GT_free(e);
  //   EXPECT_EQ(rc, IOK);

  //   rc = pbcext_element_GT_free(e2);
  //   EXPECT_EQ(rc, IOK);

  //   free(dst);    

  // }

  // TEST_F(PBCTest, InitGTRandomDumpExportImportFree) {

  //   pbcext_element_GT_t *e, *e2;
  //   unsigned char *dst;
  //   uint64_t len, len2;
  //   int rc;

  //   e = pbcext_element_GT_init();
  //   EXPECT_NE(e, nullptr);

  //   rc = pbcext_element_GT_random(e);
  //   EXPECT_NE(rc, IERROR);

  //   dst = nullptr;
  //   rc = pbcext_dump_element_GT_bytes(&dst, &len, e);
  //   EXPECT_NE(rc, IERROR);
  //   EXPECT_GT(len, 0);
  //   EXPECT_NE(dst, nullptr);

  //   e2 = pbcext_element_GT_init();
  //   EXPECT_NE(e2, nullptr);

  //   rc = pbcext_get_element_GT_bytes(e2, &len2, dst);
  //   EXPECT_NE(rc, IERROR);
  //   EXPECT_EQ(len, len2);

  //   rc = pbcext_element_GT_cmp(e, e2);
  //   EXPECT_EQ(rc, 0);
    
  //   rc = pbcext_element_GT_free(e);
  //   EXPECT_EQ(rc, IOK);

  //   rc = pbcext_element_GT_free(e2);
  //   EXPECT_EQ(rc, IOK);

  //   free(dst);

  // }
  

}  // namespace pbcext

