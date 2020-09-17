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

#include "klap20.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/klap20/mem_key.h"
#include "groupsig/klap20/signature.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int klap20_sign(groupsig_signature_t *sig,
		message_t *msg,
		groupsig_key_t *memkey,
		groupsig_key_t *grpkey,
		unsigned int seed) {

  pbcext_element_Fr_t *r;
  klap20_signature_t *klap20_sig;
  klap20_grp_key_t *klap20_grpkey;
  klap20_mem_key_t *klap20_memkey;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_KLAP20_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_sig = sig->sig;
  klap20_grpkey = grpkey->key;
  klap20_memkey = memkey->key;
  r = NULL;
  rc = IOK;

  /* Randomize u, v and w */
  if (!(r = pbcext_element_Fr_init())) GOTOENDRC(IERROR, klap20_sign);
  if (pbcext_element_Fr_random(r) == IERROR) GOTOENDRC(IERROR, klap20_sign);

  if (!(klap20_sig->uu = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_sign);
  if (pbcext_element_G1_mul(klap20_sig->uu, klap20_memkey->u, r) == IERROR)
    GOTOENDRC(IERROR, klap20_sign);
  if (!(klap20_sig->vv = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_sign);
  if (pbcext_element_G1_mul(klap20_sig->vv, klap20_memkey->v, r) == IERROR)
    GOTOENDRC(IERROR, klap20_sign);
  if (!(klap20_sig->ww = pbcext_element_G1_init())) GOTOENDRC(IERROR, klap20_sign);
  if (pbcext_element_G1_mul(klap20_sig->ww, klap20_memkey->w, r) == IERROR)
    GOTOENDRC(IERROR, klap20_sign);
  
  /* Compute signature of knowledge of alpha */
  if (!(klap20_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klap20_sign);
  if (spk_dlog_G1_sign(klap20_sig->pi,
		       klap20_sig->ww,
		       klap20_sig->uu,
		       klap20_memkey->alpha,
		       msg->bytes,
		       msg->length) == IERROR)
    GOTOENDRC(IERROR, klap20_sign);
  

 klap20_sign_end:

  if (r) { pbcext_element_Fr_free(r); r = NULL; }

  if (rc == IERROR) {
    
    if (klap20_sig->uu) {
      pbcext_element_G1_free(klap20_sig->uu);
      klap20_sig->uu = NULL;
    }
    if (klap20_sig->vv) {
      pbcext_element_G1_free(klap20_sig->vv);
      klap20_sig->vv = NULL;
    }
    if (klap20_sig->ww) {
      pbcext_element_G1_free(klap20_sig->ww);
      klap20_sig->ww = NULL;
    }
    if (klap20_sig->pi) {
      spk_dlog_free(klap20_sig->pi);
      klap20_sig->pi = NULL;
    }    
    
  }
  
  return rc;
  
}

/* sign.c ends here */
