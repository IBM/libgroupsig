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

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/signature.h"
#include "bigz.h"
#include "wrappers/hash.h"
#include "wrappers/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */

int cpy06_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the CPY06 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux_<name>. */

  element_t B1, B2, B3, B4, B5, B6;
  element_t r1, r2, aux_r1r2, r3, aux_r3x, d1, d2;
  element_t br1, br2, bd1, bd2, bt, bx;
  element_t aux_xbd1, aux_ybd2, aux_e;
  element_t aux_bd1bd2, aux_br1br2, aux_bx, aux_cmul;
  hash_t *aux_c;
  byte_t *aux_bytes;
  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_mem_key_t *cpy06_memkey;
  cpy06_sysenv_t *cpy06_sysenv;
  int rc, aux_n;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  cpy06_sig = sig->sig;
  cpy06_grpkey = grpkey->key;
  cpy06_memkey = memkey->key;
  cpy06_sysenv = sysenv->data;

  /* r1,r2,r3 \in_R Z_p */
  element_init_Zr(r1, cpy06_sysenv->pairing);
  element_random(r1);
  element_init_Zr(r2, cpy06_sysenv->pairing);
  element_random(r2);
  element_init_Zr(r3, cpy06_sysenv->pairing);
  element_random(r3);

  /* d1 = t*r1 */
  element_init_Zr(d1, cpy06_sysenv->pairing);
  element_mul(d1, cpy06_memkey->t, r1);

  /* d2 = t*r2 */
  element_init_Zr(d2, cpy06_sysenv->pairing);
  element_mul(d2, cpy06_memkey->t, r2);

  /* T1 = X^r1 */
  element_init_G1(cpy06_sig->T1, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_sig->T1, cpy06_grpkey->x, r1);

  /* T2 = Y^r2 */
  element_init_G1(cpy06_sig->T2, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_sig->T2, cpy06_grpkey->y, r2);

  /* T3 = A*Z^(r1+r2) */
  element_init_Zr(aux_r1r2, cpy06_sysenv->pairing);
  element_add(aux_r1r2, r1, r2);
  element_init_G1(cpy06_sig->T3, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_sig->T3, cpy06_grpkey->z, aux_r1r2);
  element_mul(cpy06_sig->T3, cpy06_sig->T3, cpy06_memkey->A);

  /* T4 = W^r3 */
  element_init_G2(cpy06_sig->T4, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_sig->T4, cpy06_grpkey->w, r3);

  /* T5 = e(g1, T4)^x = e(g1, W)^(r3*x) */
  element_init_Zr(aux_r3x, cpy06_sysenv->pairing);
  element_mul(aux_r3x, r3, cpy06_memkey->x);
  element_init_GT(cpy06_sig->T5, cpy06_sysenv->pairing);
  element_pow_zn(cpy06_sig->T5, cpy06_grpkey->T5, aux_r3x);

  /* br1, br2,bd1,bd2,bt,bx \in_R Z_p */
  element_init_Zr(br1, cpy06_sysenv->pairing);
  element_random(br1);
  element_init_Zr(br2, cpy06_sysenv->pairing);
  element_random(br2);
  element_init_Zr(bd1, cpy06_sysenv->pairing);
  element_random(bd1);
  element_init_Zr(bd2, cpy06_sysenv->pairing);
  element_random(bd2);
  element_init_Zr(bt, cpy06_sysenv->pairing);
  element_random(bt);
  element_init_Zr(bx, cpy06_sysenv->pairing);
  element_random(bt);

  /* B1 = X^br1 */
  element_init_G1(B1, cpy06_sysenv->pairing);
  element_pow_zn(B1, cpy06_grpkey->x, br1);

  /* B2 = Y^br2 */
  element_init_G1(B2, cpy06_sysenv->pairing);
  element_pow_zn(B2, cpy06_grpkey->y, br2);
  
  /* B3 = T1^bt/X^bd1 */
  element_init_G1(B3, cpy06_sysenv->pairing);
  element_pow_zn(B3, cpy06_sig->T1, bt);
  element_init_G1(aux_xbd1, cpy06_sysenv->pairing);
  element_pow_zn(aux_xbd1, cpy06_grpkey->x, bd1);
  element_div(B3, B3, aux_xbd1);

  /* B4 = T2^bt/Y^bd2 */
  element_init_G1(B4, cpy06_sysenv->pairing);
  element_pow_zn(B4, cpy06_sig->T2, bt);
  element_init_G1(aux_ybd2, cpy06_sysenv->pairing);
  element_pow_zn(aux_ybd2, cpy06_grpkey->y, bd2);
  element_div(B4, B4, aux_ybd2);

  /* B5 = e(g1,T4)^bx */
  element_init_GT(B5, cpy06_sysenv->pairing);
  element_pairing(B5, cpy06_grpkey->g1, cpy06_sig->T4);
  element_pow_zn(B5, B5, bx);

  /* B6 = e(T3,g2)^bt * e(z,g2)^(-bd1-bd2) * e(z,r)^(-br1-br2) * e(g1,g2)^(-bx) */
  
  /* [temp] B6 = e(T3,g2)^bt */
  element_init_GT(B6, cpy06_sysenv->pairing);
  element_pairing(B6, cpy06_sig->T3, cpy06_grpkey->g2);
  element_pow_zn(B6, B6, bt);

  /* aux_e: the rest (with the help of the optimizations is easier...) */
  
  /* (-bd1-bd2) */
  element_init_Zr(aux_bd1bd2, cpy06_sysenv->pairing);
  element_neg(aux_bd1bd2, bd1);
  element_sub(aux_bd1bd2, aux_bd1bd2, bd2);

  /* (-br1-br2) */
  element_init_Zr(aux_br1br2, cpy06_sysenv->pairing);
  element_neg(aux_br1br2, br1);
  element_sub(aux_br1br2, aux_br1br2, br2);

  /* -bx */
  element_init_Zr(aux_bx, cpy06_sysenv->pairing);
  element_neg(aux_bx, bx);

  element_init_GT(aux_e, cpy06_sysenv->pairing);
  element_pow3_zn(aux_e, 
		  cpy06_grpkey->e2, aux_bd1bd2, 
		  cpy06_grpkey->e3, aux_br1br2,
		  cpy06_grpkey->e4, aux_bx);

  element_mul(B6, B6, aux_e);
  

  /* c = hash(M,T1,T2,T3,T4,T5,B1,B2,B3,B4,B5,B6) \in Zp */
  if(!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, cpy06_sign);

  /* Push the message */
  if(hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T1 */
  aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, cpy06_sig->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, cpy06_sig->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, cpy06_sig->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, cpy06_sig->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B1 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
 
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B4) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B5) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B6 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_export_bytes(&aux_bytes, &aux_n, B6) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Finish the hash */
  if(hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, cpy06_sign);

  /* Get c as the element associated to the obtained hash value */
  element_init_Zr(cpy06_sig->c, cpy06_sysenv->pairing);
  element_from_hash(cpy06_sig->c, aux_c->hash, aux_c->length);

  /* Compute sr1, sr2, sd1, sd2, sx and st with the obtained c */
  element_init_Zr(aux_cmul, cpy06_sysenv->pairing);

  /* sr1 = br1 + c*r1 */
  element_init_Zr(cpy06_sig->sr1, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, r1);
  element_add(cpy06_sig->sr1, br1, aux_cmul);

  /* sr2 = br2 + c*r2 */
  element_init_Zr(cpy06_sig->sr2, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, r2);
  element_add(cpy06_sig->sr2, br2, aux_cmul);

  /* sd1 = bd1 + c*d1 */
  element_init_Zr(cpy06_sig->sd1, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, d1);
  element_add(cpy06_sig->sd1, bd1, aux_cmul);

  /* sd2 = bd2 + c*d2 */
  element_init_Zr(cpy06_sig->sd2, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, d2);
  element_add(cpy06_sig->sd2, bd2, aux_cmul);

  /* sx = bx + c*x */
  element_init_Zr(cpy06_sig->sx, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, cpy06_memkey->x);
  element_add(cpy06_sig->sx, bx, aux_cmul);

  /* sx = bt + c*t */
  element_init_Zr(cpy06_sig->st, cpy06_sysenv->pairing);
  element_mul(aux_cmul, cpy06_sig->c, cpy06_memkey->t);
  element_add(cpy06_sig->st, bt, aux_cmul);

 cpy06_sign_end:

  element_clear(B1); element_clear(B2);
  element_clear(B3); element_clear(B4);
  element_clear(B5); element_clear(B6);
  element_clear(r1); element_clear(r2);
  element_clear(aux_r1r2); element_clear(r3); 
  element_clear(aux_r3x); element_clear(aux_e);
  element_clear(br1); element_clear(br2);
  element_clear(bd1); element_clear(bd2);
  element_clear(bt); element_clear(bx);
  element_clear(aux_xbd1); element_clear(aux_ybd2);
  element_clear(aux_bd1bd2); element_clear(aux_br1br2);
  element_clear(aux_bx); element_clear(aux_cmul);

  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if(aux_c) { hash_free(aux_c); aux_c = NULL; }

  return rc;
  
}

/* sign.c ends here */
