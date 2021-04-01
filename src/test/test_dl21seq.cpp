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
#include "dl21seq.h"
#include "message.h"

using namespace std;
  
namespace groupsig {

  // The fixture for testing DL21SEQ scheme.
  class DL21SEQTest : public ::testing::Test {
  protected:
    // You can remove any or all of the following functions if their bodies
    // would be empty.
    groupsig_key_t *isskey;
    groupsig_key_t *grpkey;
    groupsig_key_t **memkey;
    uint32_t n;

    DL21SEQTest() {

      int rc;

      rc = groupsig_init(GROUPSIG_DL21SEQ_CODE, time(NULL));
      EXPECT_EQ(rc, IOK);
  
      isskey = groupsig_mgr_key_init(GROUPSIG_DL21SEQ_CODE);
      EXPECT_NE(isskey, nullptr);

      grpkey = groupsig_grp_key_init(GROUPSIG_DL21SEQ_CODE);
      EXPECT_NE(grpkey, nullptr);

      memkey = nullptr;
      n = 0;

    }
    
    ~DL21SEQTest() override {
      groupsig_mgr_key_free(isskey); isskey = NULL;
      groupsig_grp_key_free(grpkey); grpkey = NULL;
      if (memkey) {
	for (int i=0; i<n; i++) {
	  groupsig_mem_key_free(memkey[i]); memkey[i] = NULL;
	}
	free(memkey); memkey = NULL;
      }
      groupsig_clear(GROUPSIG_DL21SEQ_CODE);      
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

	rc = groupsig_join_mgr(&m1, NULL, isskey, 0, m0, grpkey);
	ASSERT_EQ(rc, IOK);

	m2 = message_init();
	ASSERT_NE(m2, nullptr);

        rc = groupsig_join_mem(&m2, memkey[i], 1, m1, grpkey);
	ASSERT_EQ(rc, IOK);	

	m3 = message_init();
	ASSERT_NE(m3, nullptr);

	rc = groupsig_join_mgr(&m3, NULL, isskey, 2, m2, grpkey);
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
    // for DL21SEQ.
  };


  TEST_F(DL21SEQTest, GetCodeFromStr) {

    int rc;
    uint8_t scheme;

    rc = groupsig_get_code_from_str(&scheme, (char *) GROUPSIG_DL21SEQ_NAME);
    EXPECT_EQ(rc, IOK);

    EXPECT_EQ(scheme, GROUPSIG_DL21SEQ_CODE);

  }

  // Tests that the DL21SEQ constructor creates the required keys.
  TEST_F(DL21SEQTest, CreatesGrpAndMgrKeys) {

    /* Scheme is set to DL21SEQ */
    EXPECT_EQ(grpkey->scheme, GROUPSIG_DL21SEQ_CODE);
    EXPECT_EQ(isskey->scheme, GROUPSIG_DL21SEQ_CODE);
    
  }

  /* groupsig_get_joinstart must return 0 */
  TEST_F(DL21SEQTest, CheckJoinStart) {

    int rc;
    uint8_t start;
    
    rc = groupsig_get_joinstart(GROUPSIG_DL21SEQ_CODE, &start);
    EXPECT_EQ(rc, IOK);
    
    EXPECT_EQ(start, 0);
    
  }

  /* groupsig_get_joinseq must return 3 */
  TEST_F(DL21SEQTest, CheckJoinSeq) {

    int rc;
    uint8_t seq;
    
    rc = groupsig_get_joinseq(GROUPSIG_DL21SEQ_CODE, &seq);
    EXPECT_EQ(rc, IOK);
    
    EXPECT_EQ(seq, 3);    

  }  

  /* Successfully adds a group member */
  TEST_F(DL21SEQTest, AddsNewMember) {

    int rc;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    addMembers(1);

    EXPECT_EQ(memkey[0]->scheme, GROUPSIG_DL21SEQ_CODE);    

  }

  /* Successfully initializes a signature */
  TEST_F(DL21SEQTest, InitializeSignature) {

    groupsig_signature_t *sig;
    int rc;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);
    
    EXPECT_EQ(sig->scheme, GROUPSIG_DL21SEQ_CODE);

    groupsig_signature_free(sig);
    sig = nullptr;

  }

  /* Successfully creates a valid signature */
  TEST_F(DL21SEQTest, SignVerifyValid) {

    groupsig_signature_t *sig;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
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
  TEST_F(DL21SEQTest, SignVerifyWrongMessage) {

    groupsig_signature_t *sig;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *)
			      "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Use a wrong message for verification */
    msg2 = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, Worlds!\" }");
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

  /* Successfully links 2 signatures by the same user */
  TEST_F(DL21SEQTest, SuccessfullyLinkSigsSameUser) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Add one member */
    addMembers(1);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig1;
    sigs[1] = sig2;
    
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_link(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);
    
    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }

    /* Fails to link 2 signatures by different users */
  TEST_F(DL21SEQTest, FailsLinkSigsDifferentUsers) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Add one member */
    addMembers(2);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[1], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig1;
    sigs[1] = sig2;
    
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IFAIL);
    
    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }    

  /* Successfully seqlinks 2 signatures by the same user */
  TEST_F(DL21SEQTest, SuccessfullySeqLinkSigsSameUser) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Add one member */
    addMembers(1);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig1;
    sigs[1] = sig2;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }

    /* Fails to link 2 signatures by different users */
  TEST_F(DL21SEQTest, FailsSeqLinkSigsDifferentUsers) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Add one member */
    addMembers(2);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig2, msg, memkey[1], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig1;
    sigs[1] = sig2;

    proof = NULL;
    rc = groupsig_link(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IFAIL);
    
    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }

  /* Rejects seqlink proof by same user but with wrong order (swap) */
  TEST_F(DL21SEQTest, RejectsSeqLinkProofWrongOrderSwap) {

    groupsig_signature_t *sig1, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Add one member */
    addMembers(1);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig2;
    sigs[1] = sig1;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }

  /* Rejects seqlink proof by same user but with wrong order (skip) */
  TEST_F(DL21SEQTest, RejectsSeqLinkProofWrongOrderSkip) {

    groupsig_signature_t *sig1, *sig2, *sig3, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, **msgs;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature objects */
    sig1 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig1, nullptr);

    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    sig3 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig3, nullptr);    

    /* Add one member */
    addMembers(1);

    /* 
       Initialize a message with a test string 
       (DL21SEQ messages are JSON objects with scope and message) 
    */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig1, msg, memkey[0], grpkey, 1);
    EXPECT_EQ(rc, IOK);
    
    rc = groupsig_sign(sig2, msg, memkey[0], grpkey, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_sign(sig3, msg, memkey[0], grpkey, 3);
    EXPECT_EQ(rc, IOK);    

    /* Link the signatures */
    msgs = (message_t **) malloc(sizeof(message_t *)*2);
    EXPECT_NE(msgs, nullptr);

    msgs[0] = msg;
    msgs[1] = msg;

    sigs = (groupsig_signature_t **) malloc(sizeof(groupsig_signature_t *)*2);
    EXPECT_NE(sigs, nullptr);    
    
    sigs[0] = sig1;
    sigs[1] = sig3;

    proof = nullptr;
    rc = groupsig_seqlink(&proof, grpkey, memkey[0], msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = groupsig_signature_free(sig1);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig3);
    EXPECT_EQ(rc, IOK);    
    
    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);    

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(msgs);
    free(sigs);

  }  

  /** Group key tests **/

  /* Successfully exports and imports a group key to a string */
  TEST_F(DL21SEQTest, GrpKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
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
    dst = groupsig_grp_key_import(GROUPSIG_DL21SEQ_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies a group key */
  TEST_F(DL21SEQTest, GrpKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_grp_key_init(GROUPSIG_DL21SEQ_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_copy(dst, grpkey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);    
    
  }

  /** Manager key tests **/

  /* Successfully exports and imports an issuer key to a string */
  TEST_F(DL21SEQTest, IssKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
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
    dst = groupsig_mgr_key_import(GROUPSIG_DL21SEQ_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies an issuer key */
  TEST_F(DL21SEQTest, IssKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_mgr_key_init(GROUPSIG_DL21SEQ_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_copy(dst, isskey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);
    
  }

  /** Member key tests **/

  /* Successfully exports and imports a member key to a string */
  TEST_F(DL21SEQTest, MemKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
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
    dst = groupsig_mem_key_import(GROUPSIG_DL21SEQ_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;
    
  }

  /* Successfully copies a member key */
  TEST_F(DL21SEQTest, MemKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

   /* Add one member */
    addMembers(1);    

    dst = groupsig_mem_key_init(GROUPSIG_DL21SEQ_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_copy(dst, memkey[0]);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);    
    
  }

  /** Signature object tests **/

  /* Successfully converts a signature as a string */
  TEST_F(DL21SEQTest, SignatureToString) {

    groupsig_signature_t *sig;
    message_t *msg;
    char *str;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);  

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
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
  TEST_F(DL21SEQTest, SignatureCopy) {

    groupsig_signature_t *src, *dst;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
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
    msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
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
  TEST_F(DL21SEQTest, SignatureExportImport) {

    groupsig_signature_t *sig, *imported;
    message_t *msg;
    byte_t *bytes;
    uint32_t size;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, grpkey, isskey, NULL);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *)
			      "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
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

}  // namespace groupsig

