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
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/signature.h"
#include "wrappers/hash.h"
#include "wrappers/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */


/* Public functions */

int cpy06_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof, 
				groupsig_key_t *grpkey, groupsig_signature_t **sigs, 
				uint16_t n_sigs) {

  cpy06_grp_key_t *gkey;
  cpy06_signature_t *sig;
  cpy06_proof_t *cpy06_proof;
  cpy06_sysenv_t *cpy06_sysenv;
  hash_t *hash;
  byte_t *bytes;
  element_t e, es, t5c, c;
  int rc, n;
  uint8_t i;
  
  if(!ok || !proof || proof->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !sigs || !n_sigs) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  
  gkey = (cpy06_grp_key_t *) grpkey->key;
  cpy06_proof = (cpy06_proof_t *) proof->proof;
  cpy06_sysenv = sysenv->data;

  /* Initialize the hashing environment */
  if(!(hash = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, cpy06_prove_equality_verify);

  /* We have to recover the e(g1,T4)^r objects. To do so, we divide e(g1,T4)^s/T5^c */  
  element_init_GT(e, cpy06_sysenv->pairing);
  element_init_GT(es, cpy06_sysenv->pairing);
  element_init_GT(t5c, cpy06_sysenv->pairing);

  for(i=0; i<n_sigs; i++) {

    if(sigs[i]->scheme != GROUPSIG_CPY06_CODE) {
      LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality_verify", __LINE__, LOGERROR);
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    }

    sig = (cpy06_signature_t *) sigs[i]->sig;

    element_pairing(e, gkey->g1, sig->T4);
    element_pow_zn(es, e, cpy06_proof->s);
    element_pow_zn(t5c, sig->T5, cpy06_proof->c);
    element_div(es, es, t5c);
     
    /* Put the i-th element of the array */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, es) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    mem_free(bytes); bytes = NULL;

    /* Put also the base (the e(g1,T4)'s) into the hash */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, e) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    
    mem_free(bytes); bytes = NULL;

    /* ... and T5 */
    bytes = NULL;
    if(pbcext_element_export_bytes(&bytes, &n, sig->T5) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    mem_free(bytes); bytes = NULL;
    
  }
  
  /* (2) Calculate c = hash((e(g1,T4)^r)[1] || (e(g1,T4))[1] || ... || (e(g1,T4)^r)[n] || (e(g1,T4))[n] ) */
  if(hash_finalize(hash) == IERROR) GOTOENDRC(IERROR, cpy06_prove_equality_verify);
  
  /* Now, we have to get c as a bigz_t */
  /* Now, we have to get c as an element_t */
  element_init_Zr(c, cpy06_sysenv->pairing);
  element_from_hash(c, hash->hash, hash->length);

  /* Compare the obtained c with the c received in the proof, if there is a 
     match, the proof is successful */
  errno = 0;
  if(!element_cmp(c, cpy06_proof->c))
    *ok = 1;
  else
    *ok = 0;

  /* Free resources and exit */
 cpy06_prove_equality_verify_end:
   
  element_clear(e);
  element_clear(es);
  element_clear(t5c);
   
  return rc;
   
}

/* prove_equality_verify.c ends here */
