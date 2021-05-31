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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "sys/mem.h"
#include "dl21seq.h"
#include "groupsig/dl21seq/grp_key.h"
#include "groupsig/dl21seq/mem_key.h"
#include "groupsig/dl21seq/signature.h"
#include "groupsig/dl21seq/identity.h"
#include "groupsig/dl21seq/proof.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int dl21seq_link(groupsig_proof_t **proof,
		 groupsig_key_t *grpkey,
		 groupsig_key_t *memkey,
		 message_t *msg,
		 groupsig_signature_t **sigs,
		 message_t **msgs,
		 uint32_t n) {
  
  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  dl21seq_signature_t *dl21seq_sig;
  dl21seq_mem_key_t *dl21seq_memkey;
  groupsig_proof_t *_proof;
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t ok;

  if(!proof ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21SEQ_CODE ||
     !memkey || memkey->scheme != GROUPSIG_DL21SEQ_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  dl21seq_memkey = memkey->key;

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_link);
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, dl21seq_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, dl21seq_link);

  /* Iterate through all signatures, verify, identify and
     compute batched scope and nym */
  for (i=0; i<n; i++ ) {

    /* Verify signature */
    if (dl21seq_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, dl21seq_link);
    if (!ok) GOTOENDRC(IFAIL, dl21seq_link);
    
    /* Check if it is a signature issued by memkey */
    if (dl21seq_identify(&ok, NULL, grpkey, memkey, sigs[i], msgs[i]) == IERROR)
      GOTOENDRC(IERROR, dl21seq_link);
    
    if (!ok) {
      GOTOENDRC(IFAIL, dl21seq_link);
    }
    
    /* "Accumulate" scp */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, dl21seq_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, dl21seq_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, dl21seq_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21seq_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, dl21seq_link);

  }

  /* nym_ = hscp_^y */
  if(pbcext_element_G1_mul(nym_, hscp_, dl21seq_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21seq_link);

  /* Do the SPK */

  // For now, we just use the .msg part of the msg JSON, but
  // the .scp part might come in handy in the future
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, dl21seq_link);  

  if(!(_proof = dl21seq_proof_init())) GOTOENDRC(IERROR, dl21seq_link);
  spk = ((dl21seq_proof_t *)_proof->proof)->spk;

  if(spk_dlog_G1_sign(spk, nym_, hscp_, dl21seq_memkey->y, (byte_t *) msg_msg,
		      strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, dl21seq_link);
  *proof = _proof;

 dl21seq_link_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}

/* link.c ends here */
