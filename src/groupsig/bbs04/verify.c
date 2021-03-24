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

#include "bbs04.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/signature.h"
#include "bigz.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
#include "sys/mem.h"

/* Private functions */

/* Public functions */
int bbs04_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *grpkey) {

  pbcext_element_G1_t *R1, *R2, *R4, *R5, *aux_G1;
  pbcext_element_G2_t *aux_e5, *aux_G2;
  pbcext_element_GT_t *R3, *aux_e1, *aux_e2, *aux_e3, *aux_e4;
  pbcext_element_Fr_t *c, *aux_neg;
  bbs04_signature_t *bbs04_sig;
  bbs04_grp_key_t *bbs04_grpkey;
  hash_t *aux_c;
  byte_t *aux_bytes;
  uint64_t aux_n;
  int rc;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_BBS04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_sig = sig->sig;
  bbs04_grpkey = grpkey->key;
  rc = IOK;

  R1 = R2 = R4 = R5 = aux_G1 = NULL;
  aux_e5 = aux_G2 = NULL;
  R3 = aux_e1 = aux_e2 = aux_e3 = aux_e4 = NULL;
  c = NULL;

  /* Re-derive R1, R2, R3, R4 and R5 from the signature */
  
  /* R1 = u^salpha * T1^(-c) */
  if(!(R1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(!(aux_G1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(!(aux_neg = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_neg(aux_neg, bbs04_sig->c) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(R1, bbs04_grpkey->u, bbs04_sig->salpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(aux_G1, bbs04_sig->T1, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_add(R1, R1, aux_G1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* R2 = v^sbeta * T2^(-c) */
  if(!(R2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(R2, bbs04_grpkey->v, bbs04_sig->sbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(aux_G1, bbs04_sig->T2, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_add(R2, R2, aux_G1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* R3 = e(T3,g2)^sx * e(h,w)^(-salpha-sbeta) * e(h,g2)^(-sdelta1-sdelta2) * (e(T3,w)/e(g1,g2))^c */
  /* Optimized R3 =  e(h,w)^(-salpha-sbeta) * e(h,g2)^(-sdelta1-sdelta2) * e(T3, w^c * g2 ^ sx) * e(g1, g2)^-c

  /* Optimized e1 = e(T3, w^c * g2 ^ sx) */
  if(!(aux_e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(!(aux_e5 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(!(aux_G2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G2_mul(aux_e5, bbs04_grpkey->w, bbs04_sig->c) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G2_mul(aux_G2, bbs04_grpkey->g2, bbs04_sig->sx) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G2_add(aux_e5, aux_G2, aux_e5) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_pairing(aux_e1, bbs04_sig->T3, aux_e5) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* e2 = e(h,w)^(-salpha-sbeta) */
  if(!(aux_e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_neg(aux_neg, bbs04_sig->salpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_sub(aux_neg, aux_neg, bbs04_sig->sbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_pow(aux_e2, bbs04_grpkey->hw, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  /* e3 = e(h,g2)^(-sdelta1-sdelta2) */
  if(!(aux_e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_neg(aux_neg, bbs04_sig->sdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_sub(aux_neg, aux_neg, bbs04_sig->sdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_pow(aux_e3, bbs04_grpkey->hg2, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* e4 = e(g1,g2)^-c */
  if(!(aux_e4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_pow(aux_e4, bbs04_grpkey->g1g2, bbs04_sig->c) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_inv(aux_e4, aux_e4) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* R3 = e1 * e2 * e3 * e4 */
  if(!(R3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_mul(R3, aux_e1, aux_e2) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_mul(R3, R3, aux_e3) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_GT_mul(R3, R3, aux_e4) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* R4 = T1^sx * u^(-sdelta1) */
  if(!(R4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_neg(aux_neg, bbs04_sig->sdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(aux_G1, bbs04_sig->T1, bbs04_sig->sx) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(R4, bbs04_grpkey->u, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_add(R4, R4, aux_G1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* R5 = T2^sx * v^(-sdelta2) */
  if(!(R5 = pbcext_element_G1_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_neg(aux_neg, bbs04_sig->sdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(aux_G1, bbs04_sig->T2, bbs04_sig->sx) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_mul(R5, bbs04_grpkey->v, aux_neg) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_G1_add(R5, aux_G1, R5) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* Recompute the hash-challenge c */

  /* c = hash(M,T1,T2,T3,R1,R2,R3,R4,R5) \in Zp */
  if(!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, bbs04_verify);

  /* Push the message */
  if(hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, bbs04_verify);

  /* Push T1 */
  aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;

  /* Push T2 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T2) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push T3 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, bbs04_sig->T3) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R1 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R1) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R2 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R2) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R3 */
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, R3) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R4 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R4) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;
  
  /* Push R5 */
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, R5) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);
  mem_free(aux_bytes); aux_bytes = NULL;  

  /* Finish the hash */
  if(hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, bbs04_verify);

  /* Get c as the element associated to the obtained hash value */
  if(!(c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, bbs04_verify);
  if(pbcext_element_Fr_from_hash(c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, bbs04_verify);

  /* Compare the result with the received challenge */
  if(pbcext_element_Fr_cmp(bbs04_sig->c, c)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 bbs04_verify_end:

  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if(aux_c) { hash_free(aux_c); aux_c = NULL; }

  if(R1) { pbcext_element_G1_free(R1); R1 = NULL; }
  if(R2) { pbcext_element_G1_free(R2); R2 = NULL; }
  if(R4) { pbcext_element_G1_free(R4); R4 = NULL; }
  if(R5) { pbcext_element_G1_free(R5); R5 = NULL; }
  if(aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
  if(aux_e5) { pbcext_element_G2_free(aux_e5); aux_e5 = NULL; }
  if(aux_G2) { pbcext_element_G2_free(aux_G2); aux_G2 = NULL; }
  if(R3) { pbcext_element_GT_free(R3); R3 = NULL; }
  if(aux_e1) { pbcext_element_GT_free(aux_e1); aux_e1 = NULL; }
  if(aux_e2) { pbcext_element_GT_free(aux_e2); aux_e2 = NULL; }
  if(aux_e3) { pbcext_element_GT_free(aux_e3); aux_e3 = NULL; }
  if(aux_e4) { pbcext_element_GT_free(aux_e4); aux_e4 = NULL; }
  if(c) { pbcext_element_Fr_free(c); c = NULL; }
  if(aux_neg) { pbcext_element_Fr_free(aux_neg); aux_neg = NULL; }

  return rc;

}

/* verify.c ends here */
