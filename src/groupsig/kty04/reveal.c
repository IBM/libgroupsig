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

#include "sysenv.h"
#include "bigz.h"
#include "kty04.h"
#include "groupsig/kty04/mem_key.h"
#include "groupsig/kty04/gml.h"
#include "groupsig/kty04/crl.h"
#include "groupsig/kty04/trapdoor.h"

int kty04_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index) {

  kty04_crl_entry_t *crl_entry;
  kty04_gml_entry_t *gml_entry;
  bigz_t trapdoor;

  if(!trap || trap->scheme != GROUPSIG_KTY04_CODE ||
     !gml || gml->scheme != GROUPSIG_KTY04_CODE ||
     (crl && crl->scheme != GROUPSIG_KTY04_CODE)) {
    LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  trapdoor = *(bigz_t *) trap->trap;

  /* The tracing trapdoor for the i-th member is the x field of its member key */
  if(!(gml_entry = ((kty04_gml_entry_t *) gml_get(gml, index)))) {
    LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  if(bigz_set(trapdoor, *(kty04_trapdoor_t *) gml_entry->trapdoor->trap) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  /* If we have received a CRL, update it with the "revoked" member */
  if(crl) {

    if(!(crl_entry = kty04_crl_entry_init())) {
      LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
      return IERROR;
    }

    bigz_set(crl_entry->trapdoor, trapdoor);

    if(kty04_identity_copy(crl_entry->id, gml_entry->id) == IERROR) {
      LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
      kty04_crl_entry_free(crl_entry);
      return IERROR;
    }

    if(kty04_crl_insert(crl, crl_entry) == IERROR) {
      LOG_EINVAL(&logger, __FILE__, "kty04_reveal", __LINE__, LOGERROR);
      kty04_crl_entry_free(crl_entry);
      return IERROR;
    }

  }

  return IOK;
}

/* reveal.c ends here */
