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

#include "ps16.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/signature.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
#include "sys/mem.h"

/* Private functions */

/* Public functions */
int ps16_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *grpkey) {

  pbcext_element_Fr_t *c;
  pbcext_element_G1_t *aux_G1;
  pbcext_element_GT_t *e1, *e2, *e3;
  ps16_signature_t *ps16_sig;
  ps16_grp_key_t *ps16_grpkey;
  hash_t *aux_c;
  byte_t *aux_bytes;
  uint64_t len;
  int rc;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_PS16_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_sig = sig->sig;
  ps16_grpkey = grpkey->key;
  rc = IOK;

  c = NULL;
  aux_G1 = NULL;
  e1 = e2 = e3 = NULL;
  aux_c = NULL;
  aux_bytes = NULL;

  if (!(aux_G1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_verify);

  /* e1 = e(sigma1^-1,X) */
  if (pbcext_element_G1_neg(aux_G1, ps16_sig->sigma1) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  if (!(e1 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_pairing(e1, aux_G1, ps16_grpkey->X)) GOTOENDRC(IERROR, ps16_verify);
  
  /* e2 = e(sigma2,gg) */
  if (!(e2 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_pairing(e2, ps16_sig->sigma2, ps16_grpkey->gg)) GOTOENDRC(IERROR, ps16_verify);
  
  /* e3 = e(sigma1^s,Y) */
  if (pbcext_element_G1_mul(aux_G1, ps16_sig->sigma1, ps16_sig->s) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  if (!(e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_pairing(e3, aux_G1, ps16_grpkey->Y)) GOTOENDRC(IERROR, ps16_verify);
  
  /* R = (e1*e2)^-c*e3 */
  if (pbcext_element_GT_mul(e1, e1, e2) == IERROR) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_element_GT_pow(e1, e1, ps16_sig->c) == IERROR) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_element_GT_inv(e1, e1) == IERROR) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_element_GT_mul(e1, e1, e3) == IERROR) GOTOENDRC(IERROR, ps16_verify);

  /* c = Hash(sigma1,sigma2,R,m) */
  if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ps16_verify);

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, ps16_sig->sigma1) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, ps16_sig->sigma2) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  mem_free(aux_bytes); aux_bytes = NULL;  

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, e1) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);
  mem_free(aux_bytes); aux_bytes = NULL;  

  if (hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, ps16_verify);  
  mem_free(aux_bytes); aux_bytes = NULL;

  if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, ps16_verify);

  /* Complete the sig */
  if (!(c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_verify);
  if (pbcext_element_Fr_from_hash(c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, ps16_verify);

  /* Compare the result with the received challenge */
  if (pbcext_element_Fr_cmp(ps16_sig->c, c)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 ps16_verify_end:

  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }
  if (aux_c) { hash_free(aux_c); aux_c = NULL; }
  if (aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }

  return rc;

}

/* verify.c ends here */
