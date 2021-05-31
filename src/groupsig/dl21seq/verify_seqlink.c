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
#include "sys/mem.h"
#include "dl21seq.h"
#include "groupsig/dl21seq/grp_key.h"
#include "groupsig/dl21seq/mem_key.h"
#include "groupsig/dl21seq/signature.h"
#include "groupsig/dl21seq/identity.h"
#include "groupsig/dl21seq/proof.h"
#include "shim/hash.h"
#include "misc/misc.h"

static int _dl21seq_verify_sequence(uint8_t *ok,
				    dl21seq_proof_t *proof,
				    groupsig_signature_t **sigs) {

  dl21seq_signature_t *dl21seq_sig;
  hash_t *hc;
  byte_t *aux;
  uint64_t n;
  uint32_t i, j;
  int rc;

  if (!proof || !sigs || !proof->n) {
    LOG_EINVAL(&logger, __FILE__, "_dl21seq_verify_sequence",
	       __LINE__, LOGERROR);
    return IERROR; 
  }

  rc = IOK;
  n = proof->n;

  /* Iterate through sigs and check that sig[i]->seq1 = Hash(x[i]) and
     sig[i]->seq2 = Hash(x[i] xor x[i-1]) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _dl21seq_verify_sequence);
  if(hash_update(hc, proof->x[0], proof->xlen[0]) == IERROR)
    GOTOENDRC(IERROR, _dl21seq_verify_sequence);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _dl21seq_verify_sequence);
  dl21seq_sig = sigs[0]->sig;

  if(memcmp(hc->hash, dl21seq_sig->seq->seq1, dl21seq_sig->seq->len1)) {
    *ok = 0;
    GOTOENDRC(IOK, _dl21seq_verify_sequence);
  }
  hash_free(hc); hc = NULL;
  
  for (i=1; i<n; i++) {

    /* Check sig[i]->seq1 */
    dl21seq_sig = sigs[i]->sig;
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    if(hash_update(hc, proof->x[i], proof->xlen[i]) == IERROR)
      GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _dl21seq_verify_sequence);

    if(memcmp(hc->hash, dl21seq_sig->seq->seq1, dl21seq_sig->seq->len1)) {
      *ok = 0;
      GOTOENDRC(IOK, _dl21seq_verify_sequence);
    }
    hash_free(hc); hc = NULL;

    /* Check sig[i]->seq2 */

    /* This dynamic memory can probably be made static for efficiency (checking 
       max size) */
    if(!(aux = (byte_t *) mem_malloc(sizeof(byte_t)*proof->xlen[i]))) {
      GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    }
    
    for(j=0; j<proof->xlen[i]; j++) { aux[j] = proof->x[i-1][j] ^ proof->x[i][j]; }
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    if(hash_update(hc, aux, proof->xlen[i]) == IERROR)
      GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _dl21seq_verify_sequence);
    if(memcmp(hc->hash, dl21seq_sig->seq->seq2, dl21seq_sig->seq->len2)) {
      *ok = 0;
      GOTOENDRC(IOK, _dl21seq_verify_sequence);
    }
    hash_free(hc); hc = NULL;
    mem_free(aux); aux = NULL;

  }

  *ok = 1;

  /* Compare the produced values with the  */
  
 _dl21seq_verify_sequence_end:

  if (hc) { hash_free(hc); hc = NULL; }
  if (aux) { mem_free(aux); aux = NULL; }

  return rc;
  
}

int dl21seq_verify_seqlink(uint8_t *ok,
			   groupsig_key_t *grpkey,
			   groupsig_proof_t *proof,
			   message_t *msg,
			   groupsig_signature_t **sigs,
			   message_t **msgs,
			   uint32_t n) {
  
  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  dl21seq_signature_t *dl21seq_sig;
  /* dl21seq_sysenv_t *dl21seq_sysenv; */
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t _ok;

  if(!ok || !proof || proof->scheme != GROUPSIG_DL21SEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21SEQ_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_verify_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK; _ok = 0;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_verify_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_verify_link);
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, dl21seq_verify_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21seq_verify_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, dl21seq_verify_link);

  /* Iterate through all signatures, verify, identify and
     compute batched scope and nym */
  for (i=0; i<n; i++ ) {

    /* Verify signature */
    if (dl21seq_verify(&_ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);
    
    if (!_ok)  GOTOENDRC(IOK, dl21seq_verify_link);
	    
    /* "Accumulate" scp */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);

    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, dl21seq_verify_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21seq_verify_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);

    /* "Accumulate" nym */
    dl21seq_sig = (dl21seq_signature_t *) sigs[i]->sig;
    if(pbcext_element_G1_add(nym_, nym_, dl21seq_sig->nym) == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);

  }

  /* Verify the SPK */
  
  // For now, we just use the .msg part of the msg JSON, but
  // the .scp part might come in handy in the future
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, dl21seq_verify_link);

  spk = ((dl21seq_proof_t *) proof->proof)->spk;
  if(spk_dlog_G1_verify(&_ok, nym_, hscp_, spk, (byte_t *) msg_msg,
			strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, dl21seq_verify_link);

  if (!_ok) GOTOENDRC(IOK, dl21seq_verify_link);

  /* Recompute the sequence information from the proof, and check it */
  if (_dl21seq_verify_sequence(&_ok, proof->proof, sigs) == IERROR)
      GOTOENDRC(IERROR, dl21seq_verify_link);

 dl21seq_verify_link_end:

  *ok = _ok;
    
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}

/* link.c ends here */
