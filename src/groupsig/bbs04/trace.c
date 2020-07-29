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
#include <stdint.h>
#include <errno.h>

#include "include/crl.h"
#include "bigz.h"
#include "bbs04.h"
#include "groupsig/bbs04/signature.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mgr_key.h"
#include "groupsig/bbs04/crl.h"
#include "groupsig/bbs04/gml.h"
#include "groupsig/bbs04/trapdoor.h"
#include "groupsig/bbs04/identity.h"

int bbs04_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml) {

  /* bbs04_signature_t *bbs04_sig; */
  /* bbs04_grp_key_t *gkey; */
  /* bbs04_mgr_key_t *mkey; */
  /* identity_t *id; */
  /* trapdoor_t *trap, *trapi; */
  /* uint64_t i; */
  /* uint8_t revoked; */

  /* if(!ok || !sig || sig->scheme != GROUPSIG_BBS04_CODE || */
  /*    !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE || */
  /*    !mgrkey || mgrkey->scheme != GROUPSIG_BBS04_CODE || */
  /*    !gml || !crl) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* gkey = (bbs04_grp_key_t *) grpkey->key; */
  /* mkey = (bbs04_mgr_key_t *) mgrkey->key; */
  /* bbs04_sig = (bbs04_signature_t *) sig->sig; */

  /* /\* In BBS04, tracing implies opening the signature to get the signer's  */
  /*    identity, and using the signer's identity to get her A, which */
  /*    is then matched against those of the users in a CRL *\/ */
  /* if(!(id = bbs04_identity_init())) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* /\* Open the signature *\/ */
  /* if(bbs04_open(id, NULL, crl, sig, grpkey, mgrkey, gml) == IERROR) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   return IERROR; */
  /* } */

  /* if(!(trap = bbs04_trapdoor_init())) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   return IERROR; */
  /* } */

  /* /\* We pass a NULL crl because we do not want to update it *\/ */
  /* if(bbs04_reveal(trap, NULL, gml, *(bbs04_identity_t *) id->id) == IERROR) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*   identity_free(id); id = NULL; */
  /*   trapdoor_free(trap); trap = NULL; */
  /*   return IERROR; */
  /* } */
  
  /* i = 0; revoked = 0; */
  /* while(i < crl->n) { */

  /*   if(!(trapi = bbs04_trapdoor_init())) { */
  /*     LOG_EINVAL(&logger, __FILE__, "bbs04_trace", __LINE__, LOGERROR); */
  /*     identity_free(id); id = NULL; */
  /*     trapdoor_free(trap); trap = NULL; */
  /*     return IERROR; */
  /*   } */

  /*   /\* Get the next trapdoor to test *\/ */
  /*   trapi = ((bbs04_crl_entry_t *) crl_get(crl, i))->trapdoor; */
  
  /*   if(!element_cmp(((bbs04_trapdoor_t *) trap->trap)->open, */
  /* 		    ((bbs04_trapdoor_t *) trapi->trap)->open)) { */
  /*     revoked = 1; */
  /*     break; */
  /*   } */

  /*   /\* trapdoor_free(trapi); trapi = NULL; *\/ */

  /*   i++; */

  /* } */

  /* *ok = revoked; */

  /* identity_free(id); id = NULL; */
  /* trapdoor_free(trap); trap = NULL; */

  return IOK;


}

/* trace.c ends here */
