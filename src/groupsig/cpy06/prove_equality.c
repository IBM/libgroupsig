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

#include "cpy06.h"
#include "groupsig/cpy06/proof.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/signature.h"
#include "wrappers/hash.h"
#include "wrappers/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */


/* Public functions */

int cpy06_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey, 
			 groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs) {

  cpy06_grp_key_t *gkey;
  cpy06_mem_key_t *mkey;
  groupsig_signature_t *sig;
  cpy06_signature_t *cpy06_sig;
  cpy06_proof_t *cpy06_proof;
  cpy06_sysenv_t *cpy06_sysenv;
  byte_t *bytes;
  hash_t *hash;
  element_t r, e, er;
  int rc, n;
  uint8_t i;

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE ||
     !memkey || memkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !sigs || !n_sigs) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality", __LINE__, LOGERROR);
    return IERROR;
  }
   
  rc = IOK;
   
  gkey = (cpy06_grp_key_t *) grpkey->key;
  mkey = (cpy06_mem_key_t *) memkey->key;
  cpy06_proof = (cpy06_proof_t *) proof->proof;
  cpy06_sysenv = sysenv->data;
   
  /* Initialize the hashing environment */
  if(!(hash = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, cpy06_prove_equality);
   
  /* Get random r */
  element_init_Zr(r, cpy06_sysenv->pairing);
  element_random(r);

  /* To create the proof, we make use of the T4 and T5 objects of the signatures. 
     The knowledge of the discrete logarithm of T5 to the base e(g1,T4) is used in 
     normal signature claims. In the same way, given two signatures (allegedly) 
     issued by the same member, with corresponding objects T4, T5, T4' and T5', we 
     prove here that the discrete logarithm of T5 to the base e(g1,T4) is the same 
     to that of T5' to the base e(g1,T4'). */

  
  /* (1) Raise e(g1,T4) of each received signature to r, and put it into the hash. */
  element_init_GT(e, cpy06_sysenv->pairing);
  element_init_GT(er, cpy06_sysenv->pairing);

  for(i=0; i<n_sigs; i++) {

    /* Get the next signature in the line... */
    sig = (groupsig_signature_t *) sigs[i];

    if(sig->scheme != GROUPSIG_CPY06_CODE) {
      LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality", __LINE__, LOGERROR);
      GOTOENDRC(IERROR, cpy06_prove_equality);
    }

    cpy06_sig = (cpy06_signature_t *) sig->sig;

    element_pairing(e, gkey->g1, cpy06_sig->T4);
    element_pow_zn(er, e, r);
         
    /* Put the i-th e(g1,T4)^r element of the array */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, er) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality);

    mem_free(bytes); bytes = NULL;

    /* Put the also the base ( = e(g1,T4) ) into the hash */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, e) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality);

    mem_free(bytes); bytes = NULL;

    /* ... and T5 */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, cpy06_sig->T5) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality);

    mem_free(bytes); bytes = NULL;
    
  }
    
  /* (2) Calculate c = hash((e(g1,T4)^r)[1] || (e(g1,T4))[1] || ... || (e(g1,T4)^r)[n] || (e(g1,T4))[n] ) */
  if(hash_finalize(hash) == IERROR) GOTOENDRC(IERROR, cpy06_prove_equality);

  /* Now, we have to get c as an element_t */
  element_init_Zr(cpy06_proof->c, cpy06_sysenv->pairing);
  element_from_hash(cpy06_proof->c, hash->hash, hash->length);

  /* (3) To end, get s = r - c*x */
  element_init_Zr(cpy06_proof->s, cpy06_sysenv->pairing);
  element_mul(cpy06_proof->s, cpy06_proof->c, mkey->x);
  element_add(cpy06_proof->s, r, cpy06_proof->s);

  /* Free resources and exit */
 cpy06_prove_equality_end:
 
  element_clear(r);
  element_clear(e);
  element_clear(er);

  return rc;
   
}

/* prove_equality.c ends here */
