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
#include "gl19.h"
#include "logger.h"
#include "bigz.h"
#include "sys/mem.h"
#include "groupsig/gl19/bld_key.h"
#include "groupsig/gl19/grp_key.h"
#include "groupsig/gl19/mgr_key.h"
#include "groupsig/gl19/signature.h"
#include "groupsig/gl19/blindsig.h"
#include "groupsig/gl19/identity.h"

int gl19_unblind(identity_t *nym, groupsig_signature_t *sig,
		 groupsig_blindsig_t *bsig,
		 groupsig_key_t *grpkey, groupsig_key_t *bldkey,
		 message_t *msg) {
  
  pbcext_element_Fr_t *aux_zn;
  pbcext_element_G1_t *aux_G1;
  char *s_G1;
  gl19_identity_t *gl19_id;
  gl19_blindsig_t *gl19_bsig;
  gl19_bld_key_t *gl19_bldkey;
  int rc;

  if(!nym || nym->scheme != GROUPSIG_GL19_CODE ||
     !bsig || bsig->scheme != GROUPSIG_GL19_CODE ||
     !bldkey || bldkey->scheme != GROUPSIG_GL19_CODE ||
     !msg) {
    LOG_EINVAL(&logger, __FILE__, "gl19_unblind", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  s_G1 = NULL;
  aux_G1 = NULL; aux_zn = NULL;
  
  gl19_id = nym->id;
  gl19_bsig = bsig->sig;
  gl19_bldkey = bldkey->key;

  if (!gl19_bldkey->sk) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_unblind", __LINE__,
		   "Private key needed to unblind.", LOGERROR);
    return IERROR;
  }

  /* Decrypt the pseudonym with the blinding private key */
  if(!(aux_zn = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_unblind);
  if(pbcext_element_Fr_neg(aux_zn, gl19_bldkey->sk) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);
  if(pbcext_element_G1_mul(gl19_id, gl19_bsig->nym1, aux_zn) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);
  if(pbcext_element_G1_add(gl19_id, gl19_id, gl19_bsig->nym2) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);

  /* Decrypt the (hashed) message with the blinding private key */
  if(!(aux_G1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_unblind);
  if(pbcext_element_G1_mul(aux_G1, gl19_bsig->c1, aux_zn) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);
  if(pbcext_element_G1_add(aux_G1, gl19_bsig->c2, aux_G1) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);

  /* Update the received message with the string representation of aux_G1 */
  if(!(s_G1 = pbcext_element_G1_to_b64(aux_G1)))
    GOTOENDRC(IERROR, gl19_unblind);
    
  if(message_set_bytes_from_string(msg, s_G1) == IERROR)
    GOTOENDRC(IERROR, gl19_unblind);

 gl19_unblind_end:

  if (rc == IERROR) {
    if (gl19_id) { pbcext_element_G1_free(gl19_id); gl19_id = NULL; }
  }

  if (s_G1) { mem_free(s_G1); s_G1 = NULL; }
  if (aux_G1) { pbcext_element_G1_free(aux_G1); aux_G1 = NULL; }
  if (aux_zn) { pbcext_element_Fr_free(aux_zn); aux_zn = NULL; }

  return IOK;

}

/* unblind.c ends here */
