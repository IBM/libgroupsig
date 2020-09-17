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

#include "klap20.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/klap20/signature.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */

/* Public functions */
int klap20_verify(uint8_t *ok,
		 groupsig_signature_t *sig,
		 message_t *msg,
		 groupsig_key_t *grpkey) {

  pbcext_element_GT_t *e1, *e2, *e3;
  klap20_signature_t *klap20_sig;
  klap20_grp_key_t *klap20_grpkey;
  int rc;
  uint8_t _ok;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_KLAP20_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_verify", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_sig = sig->sig;
  klap20_grpkey = grpkey->key;
  rc = IOK;

  e1 = e2 = e3 = NULL;
  _ok = 0;

  /* Verify SPK */
  if (spk_dlog_G1_verify(&_ok,
			 klap20_sig->ww,
			 klap20_sig->uu,
			 klap20_sig->pi,
			 msg->bytes,
			 msg->length) == IERROR)
    GOTOENDRC(IERROR, klap20_verify);

  if (!_ok) {
    *ok = 0;
    GOTOENDRC(IOK, klap20_verify);
  }

  /* e1 = e(vv,gg) */
  if (!(e1 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_verify);
  if (pbcext_pairing(e1, klap20_sig->vv, klap20_grpkey->gg))
    GOTOENDRC(IERROR, klap20_verify);
  
  /* e2 = e(uu,XX) */
  if (!(e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_verify);
  if (pbcext_pairing(e2, klap20_sig->uu, klap20_grpkey->XX))
    GOTOENDRC(IERROR, klap20_verify);
  
  /* e3 = e(ww,YY) */
  if (!(e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, klap20_verify);
  if (pbcext_pairing(e3, klap20_sig->ww, klap20_grpkey->YY))
    GOTOENDRC(IERROR, klap20_verify);

  if (pbcext_element_GT_mul(e2, e2, e3) == IERROR)
    GOTOENDRC(IERROR, klap20_verify);
  
  /* Compare the result with the received challenge */
  if (pbcext_element_GT_cmp(e1, e2)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 klap20_verify_end:

  if (e1) { pbcext_element_GT_free(e1); e1 = NULL; }
  if (e2) { pbcext_element_GT_free(e2); e2 = NULL; }
  if (e3) { pbcext_element_GT_free(e3); e3 = NULL; }

  return rc;

}

/* verify.c ends here */
