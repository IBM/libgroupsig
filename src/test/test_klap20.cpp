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
#include <limits.h>

#include "gtest/gtest.h"

#include "groupsig.h"
#include "klap20.h"
#include "message.h"

using namespace std;
  
namespace groupsig {

  // The fixture for testing KLAP20 scheme.
  class KLAP20Test : public ::testing::Test {
  protected:
    // You can remove any or all of the following functions if their bodies
    // would be empty.
    groupsig_key_t *isskey;
    groupsig_key_t *opnkey;
    groupsig_key_t *grpkey;
    gml_t *gml;
    groupsig_key_t **memkey;
    uint32_t n;

    KLAP20Test() {

      int rc;

      rc = groupsig_init(GROUPSIG_KLAP20_CODE, time(NULL));
      EXPECT_EQ(rc, IOK);
  
      isskey = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
      EXPECT_NE(isskey, nullptr);

      opnkey = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
      EXPECT_NE(opnkey, nullptr);      

      grpkey = groupsig_grp_key_init(GROUPSIG_KLAP20_CODE);
      EXPECT_NE(grpkey, nullptr);

      gml = gml_init(GROUPSIG_KLAP20_CODE);
      EXPECT_NE(gml, nullptr);      

      memkey = nullptr;
      n = 0;

    }
    
    ~KLAP20Test() override {
      groupsig_mgr_key_free(isskey); isskey = NULL;
      groupsig_mgr_key_free(opnkey); opnkey = NULL;
      groupsig_grp_key_free(grpkey); grpkey = NULL;
      gml_free(gml); gml = NULL;      
      if (memkey) {
	for (int i=0; i<n; i++) {
	  groupsig_mem_key_free(memkey[i]); memkey[i] = NULL;
	}
	free(memkey); memkey = NULL;
      }
      groupsig_clear(GROUPSIG_KLAP20_CODE);      
    }

    void addMembers(uint32_t n) {

      message_t *m0, *m1, *m2, *m3, *m4;
      int rc;
      uint32_t i;

      memkey = (groupsig_key_t **) malloc(sizeof(groupsig_key_t *)*n);
      ASSERT_NE(memkey, nullptr);

      m0 = m1 = m2 = m3 = m4 = nullptr;
      for (i=0; i<n; i++) {

	memkey[i] = groupsig_mem_key_init(grpkey->scheme);
	ASSERT_NE(memkey[i], nullptr);

	m1 = message_init();
	ASSERT_NE(m1, nullptr);

	rc = groupsig_join_mgr(&m1, gml, isskey, 0, m0, grpkey);
	ASSERT_EQ(rc, IOK);

	m2 = message_init();
	ASSERT_NE(m2, nullptr);

        rc = groupsig_join_mem(&m2, memkey[i], 1, m1, grpkey);
	ASSERT_EQ(rc, IOK);	

	m3 = message_init();
	ASSERT_NE(m3, nullptr);

	rc = groupsig_join_mgr(&m3, gml, isskey, 2, m2, grpkey);
	ASSERT_EQ(rc, IOK);

	rc = groupsig_join_mem(&m4, memkey[i], 3, m3, grpkey);
	ASSERT_EQ(rc, IOK);

	if(m0) { message_free(m0); m0 = NULL; }
	if(m1) { message_free(m1); m1 = NULL; }
	if(m2) { message_free(m2); m2 = NULL; }
	if(m3) { message_free(m3); m3 = NULL; }
	if(m4) { message_free(m4); m4 = NULL; }	
		
      }
      
      this->n = n;

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
    // for KLAP20.
  };


  TEST_F(KLAP20Test, GetCodeFromStr) {

    int rc;
    uint8_t scheme;

    rc = groupsig_get_code_from_str(&scheme, (char *) GROUPSIG_KLAP20_NAME);
    EXPECT_EQ(rc, IOK);

    EXPECT_EQ(scheme, GROUPSIG_KLAP20_CODE);

  }

  // Tests that the KLAP20 constructor creates the required keys.
  TEST_F(KLAP20Test, CreatesGrpAndMgrKeys) {

    /* Scheme is set to KLAP20 */
    EXPECT_EQ(grpkey->scheme, GROUPSIG_KLAP20_CODE);
    EXPECT_EQ(isskey->scheme, GROUPSIG_KLAP20_CODE);
    EXPECT_EQ(opnkey->scheme, GROUPSIG_KLAP20_CODE);
    
  }

  /* groupsig_get_joinstart must return 0 */
  TEST_F(KLAP20Test, CheckJoinStart) {

    int rc;
    uint8_t start;
    
    rc = groupsig_get_joinstart(GROUPSIG_KLAP20_CODE, &start);
    EXPECT_EQ(rc, IOK);
    
    EXPECT_EQ(start, 0);
    
  }

  /* groupsig_get_joinseq must return 3 */
  TEST_F(KLAP20Test, CheckJoinSeq) {

    int rc;
    uint8_t seq;
    
    rc = groupsig_get_joinseq(GROUPSIG_KLAP20_CODE, &seq);
    EXPECT_EQ(rc, IOK);
    
    EXPECT_EQ(seq, 3);    

  }  

  /* Successfully adds a group member */
  TEST_F(KLAP20Test, AddsNewMember) {

    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    
    
    addMembers(1);

    EXPECT_EQ(memkey[0]->scheme, GROUPSIG_KLAP20_CODE);    
    
  }

  /* Successfully initializes a signature */
  TEST_F(KLAP20Test, InitializeSignature) {

    groupsig_signature_t *sig;
    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);
    
    EXPECT_EQ(sig->scheme, GROUPSIG_KLAP20_CODE);

    groupsig_signature_free(sig);
    sig = nullptr;
    
  }

  /* Successfully creates a valid signature */
  TEST_F(KLAP20Test, SignVerifyValid) {

    groupsig_signature_t *sig;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    /* Verify the signature */
    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);
    
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);
    
  }

  /* Creates a valid signature, but verifies with wrong message */
  TEST_F(KLAP20Test, SignVerifyWrongMessage) {

    groupsig_signature_t *sig;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Use a wrong message for verification */
    msg2 = message_from_string((char *) "Hello, Worlds!");
    EXPECT_NE(msg2, nullptr);

    /* Verify the signature */
    rc = groupsig_verify(&b, sig, msg2, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 0 */
    EXPECT_EQ(b, 0);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg2);
    EXPECT_EQ(rc, IOK);    
    
  }

  /* Successfully verifies a batch of valid signatures by the same user */
  TEST_F(KLAP20Test, SignVerifyValidBatchSameMember) {

    groupsig_signature_t **sigs;
    message_t **msgs;
    char str[100];
    int rc;
    uint32_t i;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Add one member */
    addMembers(1);

    msgs = (message_t **) malloc(sizeof(message_t *)*10);
    EXPECT_NE(msgs, nullptr);

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*10);
    EXPECT_NE(sigs, nullptr);    
    
    for (i=0; i<10; i++) {

      /* Initialize a message with a test string */
      memset(str, 0, 100);
      sprintf(str, "Hello, World %u!\n", i);
      msgs[i] = message_from_string(str);
      EXPECT_NE(msgs[i], nullptr);

      /* Initialize the group signature object */
      sigs[i] = groupsig_signature_init(grpkey->scheme);
      EXPECT_NE(sigs[i], nullptr);      
      
      /* Sign */
      rc = groupsig_sign(sigs[i], msgs[i], memkey[0], grpkey, UINT_MAX);
      EXPECT_EQ(rc, IOK);

    }

    /* Verify the signatures */
    rc = groupsig_verify_batch(&b, sigs, msgs, 10, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    /* Free stuff */
    for (i=0; i<10; i++) {
      rc = groupsig_signature_free(sigs[i]);
      EXPECT_EQ(rc, IOK);
    
      rc = message_free(msgs[i]);
      EXPECT_EQ(rc, IOK);
    }

    free(sigs); sigs = NULL;
    free(msgs); msgs = NULL;
    
  }

  /* Successfully rejects a batch of wrong signatures by the same user */
  TEST_F(KLAP20Test, SignVerifyWrongBatchSameMember) {

    groupsig_signature_t **sigs;
    message_t **msgs;
    char str[100];
    int rc;
    uint32_t i;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Add one member */
    addMembers(1);

    msgs = (message_t **) malloc(sizeof(message_t *)*10);
    EXPECT_NE(msgs, nullptr);

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*10);
    EXPECT_NE(sigs, nullptr);    
    
    for (i=0; i<10; i++) {

      /* Initialize a message with a test string */
      memset(str, 0, 100);
      sprintf(str, "Hello, World %u!\n", i);
      msgs[i] = message_from_string(str);
      EXPECT_NE(msgs[i], nullptr);

      /* Initialize the group signature object */
      sigs[i] = groupsig_signature_init(grpkey->scheme);
      EXPECT_NE(sigs[i], nullptr);      
      
      /* Sign */
      rc = groupsig_sign(sigs[i], msgs[i], memkey[0], grpkey, UINT_MAX);
      EXPECT_EQ(rc, IOK);

    }
    
    /* Change one sig */
    memset(str, 0, 100);
    sprintf(str, "Hello, World!\n");
    message_free(msgs[0]);
    msgs[0] = message_from_string(str);
    EXPECT_NE(msgs[0], nullptr);

    /* Verify the signatures */
    rc = groupsig_verify_batch(&b, sigs, msgs, 10, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 0 */
    EXPECT_EQ(b, 0);

    /* Free stuff */
    for (i=0; i<10; i++) {
      rc = groupsig_signature_free(sigs[i]);
      EXPECT_EQ(rc, IOK);
    
      rc = message_free(msgs[i]);
      EXPECT_EQ(rc, IOK);
    }

    free(sigs); sigs = NULL;
    free(msgs); msgs = NULL;
    
  }  

  /* Successfully verifies a batch of valid signatures by different users */
  TEST_F(KLAP20Test, SignVerifyValidBatchDiffMembers) {

    groupsig_signature_t **sigs;
    message_t **msgs;
    char str[100];
    int rc;
    uint32_t i;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Add ten members */
    addMembers(10);

    msgs = (message_t **) malloc(sizeof(message_t *)*10);
    EXPECT_NE(msgs, nullptr);

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*10);
    EXPECT_NE(sigs, nullptr);    
    
    for (i=0; i<10; i++) {

      /* Initialize a message with a test string */
      memset(str, 0, 100);
      sprintf(str, "Hello, World %u!\n", i);
      msgs[i] = message_from_string(str);
      EXPECT_NE(msgs[i], nullptr);

      /* Initialize the group signature object */
      sigs[i] = groupsig_signature_init(grpkey->scheme);
      EXPECT_NE(sigs[i], nullptr);      
      
      /* Sign */
      rc = groupsig_sign(sigs[i], msgs[i], memkey[i], grpkey, UINT_MAX);
      EXPECT_EQ(rc, IOK);

    }

    /* Verify the signatures */
    rc = groupsig_verify_batch(&b, sigs, msgs, 10, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    /* Free stuff */
    for (i=0; i<10; i++) {
      rc = groupsig_signature_free(sigs[i]);
      EXPECT_EQ(rc, IOK);
    
      rc = message_free(msgs[i]);
      EXPECT_EQ(rc, IOK);
    }

    free(sigs); sigs = NULL;
    free(msgs); msgs = NULL;
    
  }

  /* Successfully rejects a batch of wrong signatures by different users */
  TEST_F(KLAP20Test, SignVerifyWrongBatchDiffMembers) {

    groupsig_signature_t **sigs;
    message_t **msgs;
    char str[100];
    int rc;
    uint32_t i;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Add ten member */
    addMembers(10);

    msgs = (message_t **) malloc(sizeof(message_t *)*10);
    EXPECT_NE(msgs, nullptr);

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*10);
    EXPECT_NE(sigs, nullptr);    
    
    for (i=0; i<10; i++) {

      /* Initialize a message with a test string */
      memset(str, 0, 100);
      sprintf(str, "Hello, World %u!\n", i);
      msgs[i] = message_from_string(str);
      EXPECT_NE(msgs[i], nullptr);

      /* Initialize the group signature object */
      sigs[i] = groupsig_signature_init(grpkey->scheme);
      EXPECT_NE(sigs[i], nullptr);      
      
      /* Sign */
      rc = groupsig_sign(sigs[i], msgs[i], memkey[i], grpkey, UINT_MAX);
      EXPECT_EQ(rc, IOK);

    }

    /* Change one sig */
    memset(str, 0, 100);
    sprintf(str, "Hello, World!\n");
    message_free(msgs[0]);
    msgs[0] = message_from_string(str);
    EXPECT_NE(msgs[0], nullptr);    

    /* Verify the signatures */
    rc = groupsig_verify_batch(&b, sigs, msgs, 10, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 0 */
    EXPECT_EQ(b, 0);

    /* Free stuff */
    for (i=0; i<10; i++) {
      rc = groupsig_signature_free(sigs[i]);
      EXPECT_EQ(rc, IOK);
    
      rc = message_free(msgs[i]);
      EXPECT_EQ(rc, IOK);
    }

    free(sigs); sigs = NULL;
    free(msgs); msgs = NULL;
    
  }  

  /* Opens a signature and produces a valid open proof */
  TEST_F(KLAP20Test, OpenSignatureValidProof) {

    groupsig_signature_t *sig;
    groupsig_proof_t *proof;
    message_t *msg;
    uint64_t index;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(2);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[1], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Open */
    proof = groupsig_proof_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(proof, nullptr);
    
    rc = groupsig_open(&index, proof, nullptr, sig, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);

    /* index must be 1 */
    EXPECT_EQ(index, 1);

    /* Verify the open proof. */
    rc = groupsig_open_verify(&b, proof, sig, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);
    
  }

  /* Opens a signature but produces a wrong open proof */
  TEST_F(KLAP20Test, OpenSignatureWrongProof) {

    groupsig_signature_t *sig0, *sig1;
    groupsig_proof_t *proof;
    message_t *msg;
    uint64_t index;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig0 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig0, nullptr);

    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);    

    /* Add one member */
    addMembers(2);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig0, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig1, msg, memkey[1], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Open */
    proof = groupsig_proof_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(proof, nullptr);
    
    rc = groupsig_open(&index, proof, nullptr, sig0, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);

    /* index must be 0 */
    EXPECT_EQ(index, 0);

    /* Verify the open proof. */
    rc = groupsig_open_verify(&b, proof, sig1, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_signature_free(sig0);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);    

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

  }  

  /** Group key tests **/

  /* Successfully exports and imports a group key to a string */
  TEST_F(KLAP20Test, GrpKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Get the size of the string to store the exported key */
    len = groupsig_grp_key_get_size(grpkey);
    EXPECT_NE(len, -1);
    
    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_grp_key_export(&bytes, &size, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);

    /* Import the group key */
    dst = groupsig_grp_key_import(GROUPSIG_KLAP20_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies a group key */
  TEST_F(KLAP20Test, GrpKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    dst = groupsig_grp_key_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_copy(dst, grpkey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);    
    
  }

  /** Manager key tests **/

  /* Successfully exports and imports an issuer key to a string */
  TEST_F(KLAP20Test, IssKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Get the size of the string to store the exported key */
    len = groupsig_mgr_key_get_size(isskey);
    EXPECT_NE(len, -1);
    
    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_mgr_key_export(&bytes, &size, isskey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);    

    /* Import the group key */
    dst = groupsig_mgr_key_import(GROUPSIG_KLAP20_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies an issuer key */
  TEST_F(KLAP20Test, IssKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    dst = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_copy(dst, isskey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);
    
  }

  /* Successfully exports and imports an opener key to a string */
  TEST_F(KLAP20Test, OpnkeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    groupsig_signature_t *sig;
    identity_t *id;
    message_t *msg;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Get the size of the string to store the exported key */
    len = groupsig_mgr_key_get_size(opnkey);
    EXPECT_NE(len, -1);

    
    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_mgr_key_export(&bytes, &size, opnkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);  

    /* Import the group key */
    dst = groupsig_mgr_key_import(GROUPSIG_KLAP20_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    /* Free stuff */
    free(bytes); bytes = nullptr;
    
    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);    
    
  }

  /* Successfully copies a converter key */
  TEST_F(KLAP20Test, OpnkeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    dst = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_copy(dst, opnkey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);
    
  }  

  /** Member key tests **/

  /* Successfully exports and imports a member key to a string */
  TEST_F(KLAP20Test, MemKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Add one member */
    addMembers(1);

    /* Get the size of the string to store the exported key */
    len = groupsig_mem_key_get_size(memkey[0]);
    EXPECT_NE(len, -1);
    
    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_mem_key_export(&bytes, &size, memkey[0]);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);

    /* Import the group key */
    dst = groupsig_mem_key_import(GROUPSIG_KLAP20_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies a member key */
  TEST_F(KLAP20Test, MemKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

   /* Add one member */
    addMembers(1);    

    dst = groupsig_mem_key_init(GROUPSIG_KLAP20_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_copy(dst, memkey[0]);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);    
    
  }
  
  /** Signature object tests **/

  /* Successfully converts a signature as a string */
  TEST_F(KLAP20Test, SignatureToString) {

    groupsig_signature_t *sig;
    message_t *msg;
    char *str;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);  

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    /* Verify the src signature */
    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);    
    
    str = groupsig_signature_to_string(sig);
    EXPECT_NE(str, nullptr);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);
    
    free(str); str = nullptr;
    
  }

  /* Successfully copies a signature */
  TEST_F(KLAP20Test, SignatureCopy) {

    groupsig_signature_t *src, *dst;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the src group signature object */
    src = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(src, nullptr);

    /* Initialize the dst group signature object */
    dst = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(dst, nullptr);    

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(src, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);
    
    /* Verify the src signature */
    rc = groupsig_verify(&b, src, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);    
    
    rc = groupsig_signature_copy(dst, src);
    EXPECT_EQ(rc, IOK);

    /* Verify the dst signature */
    rc = groupsig_verify(&b, dst, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    rc = groupsig_signature_free(dst);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(src);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);
    
  }

  /* Successfully creates a valid signature */
  TEST_F(KLAP20Test, SignatureExportImport) {

    groupsig_signature_t *sig, *imported;
    message_t *msg;
    byte_t *bytes;
    uint32_t size;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);    

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Export */
    bytes = nullptr;
    rc = groupsig_signature_export(&bytes, &size, sig);
    EXPECT_EQ(rc, IOK);
    EXPECT_NE(bytes, nullptr);

    /* Import */
    imported = groupsig_signature_import(sig->scheme, bytes, size);
    EXPECT_NE(imported, nullptr);    
    
    /* Verify the signature */
    rc = groupsig_verify(&b, imported, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    rc = groupsig_signature_free(imported);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /** GML tests **/
  
  /* Successfully exports and imports a GML */
  TEST_F(KLAP20Test, GmlExportImport) {

    byte_t *bytes;
    gml_t *imported;
    int rc;
    uint32_t size;

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, isskey, gml);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, grpkey, opnkey, gml);
    EXPECT_EQ(rc, IOK);
    
    /* Add one member */
    addMembers(1);

    /* Export */
    bytes = NULL;
    rc = gml_export(&bytes, &size, gml);
    EXPECT_EQ(rc, IOK);

    /* Import */
    imported = gml_import(GROUPSIG_KLAP20_CODE, bytes, size);
    EXPECT_NE(imported, nullptr);

    gml_free(imported);
    imported = nullptr;

    free(bytes); bytes = NULL;
    
  }  
  
  
}  // namespace groupsig

