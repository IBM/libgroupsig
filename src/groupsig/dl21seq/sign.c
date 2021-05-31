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

#include <stdlib.h>
#include <limits.h>

#include "dl21seq.h"
#include "groupsig/dl21seq/grp_key.h"
#include "groupsig/dl21seq/mem_key.h"
#include "groupsig/dl21seq/signature.h"
#include "shim/hash.h"
#include "crypto/prf.h"
#include "sys/mem.h"

static int _dl21_compute_seq(dl21seq_mem_key_t *memkey,
			     dl21seq_seqinfo_t *seq,
			     unsigned int state) {

  hash_t *hc;
  byte_t *xi, *xi1, *ni1;
  uint64_t len, i;
  unsigned int state1;
  int rc;

  if (!memkey || !seq) {
    LOG_EINVAL(&logger, __FILE__, "_dl21_compute_seq", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  xi = xi1 = ni1 = NULL;
  hc = NULL;

  /* Compute seq3 = PRF(k,state) */
  seq->seq3 = NULL;
  if (prf_compute(&seq->seq3, &seq->len3,
		  memkey->k, (byte_t*) &state, sizeof(unsigned int)) == IERROR)
    GOTOENDRC(IERROR, _dl21_compute_seq);
  
  /* Compute x_i = PRF(k',state) */
  if (prf_compute(&xi, &len, memkey->kk, seq->seq3, seq->len3) == IERROR)
    GOTOENDRC(IERROR, _dl21_compute_seq);
  
  /* seq1 = Hash(x_i) */
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _dl21_compute_seq);
  if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _dl21_compute_seq);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _dl21_compute_seq);
  if (!(seq->seq1 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
    GOTOENDRC(IERROR, _dl21_compute_seq);
  memcpy(seq->seq1, hc->hash, hc->length);
  seq->len1 = hc->length;
  hash_free(hc); hc = NULL;

  /* Compute x_{i-1} = PRF(k',PRF(k,state-1)) */
  ni1 = NULL; xi1 = NULL;
  if (state >= 1) {


    /* Recompute n_{i-1} = PRF(k,state-1) */
    state1 = state - 1;
    if (prf_compute(&ni1, &len, memkey->k,
		    (byte_t*) &state1, sizeof(unsigned int)) == IERROR)
      GOTOENDRC(IERROR, _dl21_compute_seq);
  
    if (prf_compute(&xi1, &len, memkey->kk, ni1, len) == IERROR)
      GOTOENDRC(IERROR, _dl21_compute_seq);

    /* seq2 = Hash(x_i \xor x_{i-1}) */
    for (i=0; i<len; i++) xi[i] = xi[i] ^ xi1[i];
    if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, _dl21_compute_seq);
    if(hash_update(hc, xi, len) == IERROR) GOTOENDRC(IERROR, _dl21_compute_seq);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, _dl21_compute_seq);
    if (!(seq->seq2 = (byte_t *) mem_malloc(sizeof(byte_t)*hc->length)))
      GOTOENDRC(IERROR, _dl21_compute_seq);
    memcpy(seq->seq2, hc->hash, hc->length);
    seq->len2 = hc->length;
    hash_free(hc); hc = NULL;
    
  } else {
    seq->seq2 = NULL;
    seq->len2 = 0;
  }

 _dl21_compute_seq_end:

  if (hc) { hash_free(hc); hc = NULL; }
  if (xi) { mem_free(xi); xi = NULL; }
  if (xi1) { mem_free(xi1); xi1 = NULL; }
  if (ni1) { mem_free(ni1); ni1 = NULL; }
    
  return rc;

}

/* Public functions */

int dl21seq_sign(groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *memkey, 
		 groupsig_key_t *grpkey,
		 unsigned int state) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the DL21SEQ paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk and appending a '_' for
     variables named with a hat or something similar). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux[_<name>]. */

  pbcext_element_Fr_t *r1, *r2, *r3, *ss, *negy, *aux_Zr, *x[7];
  pbcext_element_G1_t *aux, *aux_h2negr2, *A_d, *hscp;
  pbcext_element_G1_t *y[3], *g[5];
  dl21seq_signature_t *dl21seq_sig;
  dl21seq_grp_key_t *dl21seq_grpkey;
  dl21seq_mem_key_t *dl21seq_memkey;
  dl21seq_seqinfo_t *seq;
  hash_t *hc;
  char *msg_msg, *msg_scp;
  uint16_t i[6][2], prods[3];
  int rc;

  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_DL21SEQ_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21seq_sig = sig->sig;
  dl21seq_grpkey = grpkey->key;
  dl21seq_memkey = memkey->key;
  rc = IOK;

  r1 = r2 = r3 = ss = negy = aux_Zr = NULL;
  aux = aux_h2negr2 = A_d = NULL;
  msg_msg = NULL; msg_scp = NULL;
  seq = NULL;
  hc = NULL;

  /* Parse message and scope values from msg */
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(message_json_get_key(&msg_scp, msg, "$.scope") == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  
  /* r1, r2 \in_R Z_p */
  if(!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, dl21seq_sign);
  if(!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, dl21seq_sign);

  /* nym = Hash(scp)^y */
  dl21seq_sig->nym = pbcext_element_G1_init();
  hscp = pbcext_element_G1_init();
  if(!(hc = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, dl21seq_sign);
  if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21seq_sign);
  pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);

  if(pbcext_element_G1_mul(dl21seq_sig->nym, hscp, dl21seq_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign); 

  /* AA = A^r1*/
  if(!(dl21seq_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_mul(dl21seq_sig->AA, dl21seq_memkey->A, r1) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  /* A_ = AA^{-x}(g1*h1^y*h2^s)^r1 */
  /* Good thing we precomputed much of this... */
  if(!(aux = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(!(dl21seq_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(!(aux_Zr = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_add(aux, dl21seq_memkey->H, dl21seq_memkey->h2s) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_add(aux, dl21seq_grpkey->g1, aux) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_mul(aux, aux, r1) == IERROR) // aux = (g1*h1^y*h2^s)^r1
    GOTOENDRC(IERROR, dl21seq_sign); 
  if(pbcext_element_Fr_neg(aux_Zr, dl21seq_memkey->x) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_mul(dl21seq_sig->A_, dl21seq_sig->AA, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_add(dl21seq_sig->A_, dl21seq_sig->A_, aux) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  /* d = (g1*h1^y*h2^s)^r1*h2^{-r2} */
  if(!(dl21seq_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(!(aux_h2negr2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_neg(aux_Zr, r2) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_mul(dl21seq_sig->d, dl21seq_grpkey->h2, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_add(dl21seq_sig->d, aux, dl21seq_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  /* r3 = r1^{-1} */
  if(!(r3 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_inv(r3, r1) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  /* ss = s - r2*r3 */
  if(!(ss = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_mul(aux_Zr, r2, r3) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_sub(ss, dl21seq_memkey->s, aux_Zr) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  /* Auxiliar variables for the spk */
  if(pbcext_element_Fr_neg(aux_Zr, dl21seq_memkey->x) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_neg(ss, ss) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(!(negy = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_Fr_neg(negy, dl21seq_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);
  if(!(A_d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_sign);
  if(pbcext_element_G1_sub(A_d, dl21seq_sig->A_, dl21seq_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  // @TODO Check
  /* Isn't there a more concise way to do the following? */
  y[0] = dl21seq_sig->nym;
  y[1] = A_d;
  y[2] = dl21seq_grpkey->g1;

  g[0] = hscp;
  g[1] = dl21seq_sig->AA;
  g[2] = dl21seq_grpkey->h2;
  g[3] = dl21seq_sig->d;
  g[4] = dl21seq_grpkey->h1;

  x[0] = aux_Zr; // -x
  x[1] = dl21seq_memkey->y;
  x[2] = r2;
  x[3] = r3;
  x[4] = ss; // -ss
  x[5] = negy;

  i[0][0] = 1; i[0][1] = 0; // hscp^y = (g[0],x[1])
  i[1][0] = 0; i[1][1] = 1; // AA^-x = (g[1],x[0])
  i[2][0] = 2; i[2][1] = 2; // h2^r2 = (g[2],x[2])
  i[3][0] = 3; i[3][1] = 3; // d^r3 = (g[3],x[3])
  i[4][0] = 4; i[4][1] = 2; // h2^-ss = (g[2],x[4])
  i[5][0] = 5; i[5][1] = 4; // h1^-y = (g[4],x[5])

  prods[0] = 1;
  prods[1] = 2;
  prods[2] = 3;

  if(!(dl21seq_sig->pi = spk_rep_init(6))) GOTOENDRC(IERROR, dl21seq_sign);
  if(spk_rep_sign(dl21seq_sig->pi,
		  y, 3, // element_t *y, uint16_t ny,
		  g, 5, // element_t *g, uint16_t ng,
		  x, 6, // element_t *x, uint16_t nx,
		  i, 6, // uint16_t **i, uint16_t ni,
		  prods,
		  (byte_t *) msg_msg, strlen(msg_msg)) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  /* Compute seq */
  if(!(seq = (dl21seq_seqinfo_t *) mem_malloc(sizeof(dl21seq_seqinfo_t))))
    GOTOENDRC(IERROR, dl21seq_sign);

  if (_dl21_compute_seq(dl21seq_memkey, seq, state) == IERROR)
    GOTOENDRC(IERROR, dl21seq_sign);

  dl21seq_sig->seq = seq;

 dl21seq_sign_end:

  if(r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if(r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if(r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if(ss) { pbcext_element_Fr_free(ss); ss = NULL; }
  if(aux) { pbcext_element_G1_free(aux); aux = NULL; }
  if(aux_Zr) { pbcext_element_Fr_free(aux_Zr); aux = NULL; }
  if(aux_h2negr2) { pbcext_element_G1_free(aux_h2negr2); aux_h2negr2 = NULL; }
  if(negy) { pbcext_element_Fr_free(negy); negy = NULL; }
  if(A_d) { pbcext_element_G1_free(A_d); A_d = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }
  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(msg_scp) { mem_free(msg_scp); msg_scp = NULL; }

  if (rc == IERROR) {
    
    if(dl21seq_sig->nym) {
      pbcext_element_G1_free(dl21seq_sig->nym);
      dl21seq_sig->nym = NULL;
    }
    if(dl21seq_sig->AA) {
      pbcext_element_G1_free(dl21seq_sig->AA);
      dl21seq_sig->AA = NULL;
    }
    if(dl21seq_sig->A_) {
      pbcext_element_G1_free(dl21seq_sig->A_);
      dl21seq_sig->A_ = NULL;
    }
    if(dl21seq_sig->d) {
      pbcext_element_G1_free(dl21seq_sig->d);
      dl21seq_sig->d = NULL;
    }
    if(dl21seq_sig->pi) {
      spk_rep_free(dl21seq_sig->pi);
      dl21seq_sig->pi = NULL;
    }
    
  }
  
  return rc;
  
}

/* sign.c ends here */
