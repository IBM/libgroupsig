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
#include "bigz.h"

using namespace std;

/*
 * Note: These tests do not evaluate the precission (and not even the 
 * correctness) of operations on very large numbers. They rather test
 * that the shim'ed libraries implement the required functionality.
 * I.e., correctness & precission is assumed (so, be careful on what
 * libraries you use as engine for big numbers...)
 */
namespace bigz {

  // The fixture for testing operations with big numbers.
  class BigzTest : public ::testing::Test {
  protected:

    BigzTest() {
      sysenv = sysenv_init(0);
    }
    
    ~BigzTest() override {
      sysenv_free(sysenv);
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
    // for GL19.
  };

  /* Tests that a big integer is initialized and freed correctly */
  TEST_F(BigzTest, InitFree) {

    bigz_t b;
    int rc;

    b = bigz_init();
    EXPECT_NE(b, nullptr);

    rc = bigz_free(b);
    EXPECT_EQ(rc, IOK);

  }

  /* Tests that a big integer is set correctly from an unisgned long int */
  TEST_F(BigzTest, SetFromUIAndCmp) {

    bigz_t b;
    int rc;

    b = bigz_init_set_ui(100);
    EXPECT_NE(b, nullptr);

    rc = bigz_cmp_ui(b, 100);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b);
    EXPECT_EQ(rc, IOK);

  }

  /* Tests that a big integer is initialized and set from another big integer */
  TEST_F(BigzTest, InitSetFromBigzAndCmp) {

    bigz_t b1, b2;
    int rc;

    b1 = bigz_init_set_ui(100);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set(b1);
    EXPECT_NE(b2, nullptr);

    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);    

  }

  /* Tests sign. */
  TEST_F(BigzTest, DetectSign) {

    bigz_t b;
    int rc;

    b = bigz_init_set_ui(100);
    EXPECT_NE(b, nullptr);

    rc = bigz_sgn(b);
    EXPECT_EQ(rc, 1);

    rc = bigz_neg(b, b);
    EXPECT_EQ(rc, IOK);

    rc = bigz_sgn(b);
    EXPECT_EQ(rc, -1);   

    rc = bigz_set_ui(b, 0);
    EXPECT_EQ(rc, IOK);

    rc = bigz_sgn(b);
    EXPECT_EQ(rc, 0);   
        
    rc = bigz_free(b);
    EXPECT_EQ(rc, IOK);  

  }

  /* Tests sums. */
  TEST_F(BigzTest, AddAndCmp) {

    bigz_t b1, b2;
    int rc;

    b1 = bigz_init_set_ui(100);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set(b1);
    EXPECT_NE(b2, nullptr);

    rc = bigz_add(b2, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 200);
    EXPECT_EQ(rc, 0);

    rc = bigz_add_ui(b2, b2, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 300);
    EXPECT_EQ(rc, 0);
        
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);    

  }

  /* Tests subtractions. */
  TEST_F(BigzTest, SubAndCmp) {

    bigz_t b1, b2;
    int rc;

    /* b1 = 100 */
    b1 = bigz_init_set_ui(100);
    EXPECT_NE(b1, nullptr);

    /* b2 = 100 */
    b2 = bigz_init_set(b1);
    EXPECT_NE(b2, nullptr);

    /* b2 = 0 */
    rc = bigz_sub(b2, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 0);
    EXPECT_EQ(rc, 0);

    /* b2 = 100 */
    rc = bigz_set_ui(b2, 100);
    EXPECT_EQ(rc, IOK);

    /* b2 = 0 */
    rc = bigz_sub_ui(b2, b2, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 0);
    EXPECT_EQ(rc, 0);
        
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);    

  }

  /* Tests multiplications. */
  TEST_F(BigzTest, MulAndCmp) {

    bigz_t b1, b2;
    int rc;

    b1 = bigz_init_set_ui(100);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set(b1);
    EXPECT_NE(b2, nullptr);

    rc = bigz_mul(b2, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 10000);
    EXPECT_EQ(rc, 0);

    rc = bigz_mul_ui(b2, b2, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b2, 1000000);
    EXPECT_EQ(rc, 0);
        
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);    

  }

  /* Tests variants of div and mod. */
  TEST_F(BigzTest, DivModAndCmp) {

    bigz_t b1, b2, b3;
    int rc;

    /* test tdiv with 100/33 */
    b1 = bigz_init_set_ui(100);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set_ui(33);
    EXPECT_NE(b2, nullptr);

    b3 = bigz_init();
    EXPECT_NE(b3, nullptr);

    rc = bigz_tdiv(b1, b2, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b1, 3);
    EXPECT_EQ(rc, 0);

    rc = bigz_cmp_ui(b2, 1);
    EXPECT_EQ(rc, 0);

    /* test tdiv (ui variant) with 100/33 */    
    bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);    

    rc = bigz_tdiv_ui(b1, b2, b1, 33);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b1, 3);
    EXPECT_EQ(rc, 0);

    rc = bigz_cmp_ui(b2, 1);
    EXPECT_EQ(rc, 0);

    /* test non divisibility */
    rc = bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_set_ui(b2, 33);
    EXPECT_EQ(rc, IOK);

    rc = bigz_divisible_p(b1, b2);
    EXPECT_EQ(rc, 0);

    /* test divisibility */
    bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);

    bigz_set_ui(b2, 10);
    EXPECT_EQ(rc, IOK);

    rc = bigz_divisible_p(b1, b2);
    EXPECT_NE(rc, 0);

    /* Test exact division */
    rc = bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_set_ui(b2, 10);
    EXPECT_EQ(rc, IOK);

    rc = bigz_divexact(b1, b1, b2);
    EXPECT_EQ(rc, IOK);
      
    rc = bigz_cmp_ui(b1, 10);
    EXPECT_EQ(rc, IOK);

    /* Test exact division (ui variant) */
    bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_divexact_ui(b1, b1, 10);
    EXPECT_EQ(rc, IOK);    
      
    rc = bigz_cmp_ui(b1, 10);
    EXPECT_EQ(rc, IOK);

    /* Test mod */
    bigz_set_ui(b1, 100);
    EXPECT_EQ(rc, IOK);

    rc = bigz_set_ui(b2, 33);
    EXPECT_EQ(rc, IOK);    
    
    rc = bigz_mod(b3, b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_cmp_ui(b3, 1);
    EXPECT_EQ(rc, 0); 
        
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b3);
    EXPECT_EQ(rc, IOK);    

  }   

  /* Tests exponentiations. */
  TEST_F(BigzTest, ExpAndCmp) {

    bigz_t b1, b2, b3, b4;
    int rc;

    b1 = bigz_init_set_ui(10);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set_ui(2);
    EXPECT_NE(b2, nullptr);

    b3 = bigz_init_set_ui(33);
    EXPECT_NE(b3, nullptr);

    b4 = bigz_init();
    EXPECT_NE(b4, nullptr);

    /* Test powm */
    rc = bigz_powm(b4, b1, b2, b3);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b4, 1);
    EXPECT_EQ(rc, 0);

    /* Test pow_ui */
    rc = bigz_pow_ui(b4, b1, 2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b4, 100);
    EXPECT_EQ(rc, 0);

    /* Test ui_pow_ui */
    rc = bigz_ui_pow_ui(b4, 10, 2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b4, 100);
    EXPECT_EQ(rc, 0);

    /* Test invert */
    rc = bigz_set_ui(b1, 4);
    EXPECT_EQ(rc, IOK);

    rc = bigz_set_ui(b2, 7);
    EXPECT_EQ(rc, IOK);

    rc = bigz_invert(b3, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b3, 2);
    EXPECT_EQ(rc, 0);

    
    /* Free */
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b3);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b4);
    EXPECT_EQ(rc, IOK);

  }

  /* Tests prime-related algorithms. */
  TEST_F(BigzTest, Primes) {

    bigz_t b1, b2;
    int rc;

    b1 = bigz_init_set_ui(65521);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set_ui(65520);
    EXPECT_NE(b2, nullptr);

    /* Test b1 for primality (it is prime) */
    rc = bigz_probab_prime_p(b1, 25);
    EXPECT_NE(rc, 0);

    rc = bigz_probab_prime_p(b2, 25);
    EXPECT_EQ(rc, 0);

    /* Compute next prime */
    rc = bigz_nextprime(b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp_ui(b1, 65521);
    EXPECT_EQ(rc, 0);
        
    /* Free */
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

  }

  /* Tests GCD algorithm. */
  TEST_F(BigzTest, GCD) {

    bigz_t b1, b2;
    int rc;

    b1 = bigz_init_set_ui(666);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set_ui(555);
    EXPECT_NE(b2, nullptr);

    /* Compute GCD */
    rc = bigz_gcd(b1, b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_cmp_ui(b1, 111);
    EXPECT_EQ(rc, 0);
        
    /* Free */
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

  }
  
  /* Tests random number generation functions. */
  TEST_F(BigzTest, Random) {

    bigz_t b1, b2, b3;
    int rc;

    b1 = bigz_init();
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init_set_ui(1000);
    EXPECT_NE(b2, nullptr);

    b3 = bigz_init();
    EXPECT_NE(b2, nullptr);    

    /* Random picking in arbitrary range */
    rc = bigz_urandomm(b1, b2);
    EXPECT_EQ(rc, IOK);

    /* b1 must be between 0 and b2-1 */
    rc = bigz_sgn(b1);
    EXPECT_NE(rc, -1);
    
    rc = bigz_sub(b3, b1, b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_sgn(b3);
    EXPECT_EQ(rc, -1);

    /* Random picking in binary range */
    rc = bigz_urandomb(b1, 10);
    EXPECT_EQ(rc, IOK);

    /* b1 must be between 0 and 2^10-1  */
    rc = bigz_sgn(b1);
    EXPECT_NE(rc, -1);
    
    rc = bigz_sub_ui(b3, b1, 1024);
    EXPECT_EQ(rc, IOK);

    rc = bigz_sgn(b3);
    EXPECT_EQ(rc, -1);
    
    /* Free */    
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b3);
    EXPECT_EQ(rc, IOK);    

  }

  /* Test binary-related operations */
  /* Tests export-import functionality. */
  TEST_F(BigzTest, Binary) {

    // bigf_t bf;
    bigz_t b1;
    int rc;
    size_t size;

    b1 = bigz_init_set_ui(1024);
    EXPECT_NE(b1, nullptr);

    /* Get bit size */
    size = bigz_sizeinbits(b1);
    EXPECT_EQ(size, 11);

    /* Test bit */
    rc = bigz_tstbit(b1, 10);
    EXPECT_EQ(rc, 1);

    rc = bigz_tstbit(b1, 0);
    EXPECT_EQ(rc, 0);

    /* Clear bit */
    rc = bigz_clrbit(b1, 10);
    EXPECT_EQ(rc, IOK);

    rc = bigz_tstbit(b1, 10);
    EXPECT_EQ(rc, 0);

    // /* log2 */
    // bf = bigf_init();
    // EXPECT_NE(bf, nullptr);
    
    // rc = bigz_set_ui(b1, 1024);
    // EXPECT_EQ(rc, IOK);

    // rc = bigz_log2(bf, b1, 10);
    // EXPECT_EQ(rc, IOK);  
        
    /* Free */
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);


  }
  

  /* Tests export-import functionality. */
  TEST_F(BigzTest, ExportImport) {

    bigz_t b1, b2;
    char *str;
    byte_t *bytes;
    FILE *fd;
    int rc;
    size_t size;

    str = nullptr; bytes = nullptr;

    b1 = bigz_init_set_ui(1000);
    EXPECT_NE(b1, nullptr);

    b2 = bigz_init();
    EXPECT_NE(b2, nullptr);

    /* Export to hex string */
    str = bigz_get_str16(b1);
    EXPECT_NE(str, nullptr);

    /* Import back */
    rc = bigz_set_str16(b2, str);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    free(str); str = nullptr;

    /* Export to decimal string */
    str = bigz_get_str10(b1);
    EXPECT_NE(str, nullptr);

    b2 = bigz_init();
    EXPECT_NE(b2, nullptr);    

    /* Import back */
    rc = bigz_set_str10(b2, str);
    EXPECT_EQ(rc, IOK);

    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    /* Export to bytes */
    bytes = bigz_export(b1, &size);
    EXPECT_NE(bytes, nullptr);
    EXPECT_NE(size, 0);

    /* Import back */
    b2 = bigz_import(bytes, size);
    EXPECT_NE(b2, nullptr);

    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);    
    
    /* Dump to fd with sign */
    fd = fopen("test", "w");
    EXPECT_NE(fd, nullptr);

    rc = bigz_dump_bigz_fd(b1, fd);
    EXPECT_EQ(rc, IOK);

    rc = fclose(fd);
    EXPECT_EQ(rc, 0);

    /* Get from fd */
    fd = fopen("test", "r");
    EXPECT_NE(fd, nullptr);

    b2 = bigz_get_bigz_fd(fd);
    EXPECT_NE(b2, nullptr);

    rc = fclose(fd);
    EXPECT_EQ(rc, 0);
    
    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    /* Dump a negative number */
    fd = fopen("test", "w");
    EXPECT_NE(fd, nullptr);

    rc = bigz_neg(b1, b1);
    EXPECT_EQ(rc, IOK);
    
    rc = bigz_dump_bigz_fd(b1, fd);
    EXPECT_EQ(rc, IOK);

    rc = fclose(fd);
    EXPECT_EQ(rc, 0);

    /* Get from fd */
    fd = fopen("test", "r");
    EXPECT_NE(fd, nullptr);

    b2 = bigz_get_bigz_fd(fd);
    EXPECT_NE(b2, nullptr);

    rc = fclose(fd);
    EXPECT_EQ(rc, 0);
    
    rc = bigz_cmp(b1, b2);
    EXPECT_EQ(rc, 0);

    /* Free */
    rc = bigz_free(b1);
    EXPECT_EQ(rc, IOK);

    rc = bigz_free(b2);
    EXPECT_EQ(rc, IOK);

    if(str) { free(str); str = nullptr; }
    if(bytes) { free(bytes); bytes = nullptr; }

  } 

}  // namespace bigz

