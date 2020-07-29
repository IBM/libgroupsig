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
#include "kty04.h"
#include "groupsig/kty04/signature.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/crl.h"

int kty04_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml) {

  kty04_signature_t *kty04_sig;
  kty04_grp_key_t *gkey;
  bigz_t a3t, aux;
  uint64_t i;
  uint8_t revoked;

  if(!ok || !sig || sig->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !crl) {
    LOG_EINVAL(&logger, __FILE__, "kty04_trace", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = (kty04_grp_key_t *) grpkey->key;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* To test whether the signature has been issued with the member with tracing
     trapdoor "trapdoor", we have to check if sig->A[3]^trapdoor == sig->A[11]. */
  if(!(a3t = bigz_init())) return IERROR;

  i = 0; revoked = 0;
  while(i < crl->n) {

    /* Get the next trapdoor to test */
    aux = ((kty04_crl_entry_t *) crl_get(crl, i))->trapdoor;

    if(bigz_powm(a3t, kty04_sig->A[3], aux, gkey->n)) {
      bigz_free(a3t);
      return IERROR;
    }
  
    errno = 0;
    if(!bigz_cmp(a3t, kty04_sig->A[11])) {
      if(errno) {
	bigz_free(a3t);
	return IERROR;
      }
      revoked = 1;
      break;
    } else {
      if(errno) {
	bigz_free(a3t);
	return IERROR;
      }
    }

    i++;

  }

  *ok = revoked;

  bigz_free(a3t);

  return IOK;

}

/* trace.c ends here */
