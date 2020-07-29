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
#include "cpy06.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/crl.h"
#include "groupsig/cpy06/trapdoor.h"

int cpy06_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index) {

  cpy06_crl_entry_t *crl_entry;
  cpy06_gml_entry_t *gml_entry;
  trapdoor_t* crl_trap;


  if(!trap || trap->scheme != GROUPSIG_CPY06_CODE ||
     !gml || gml->scheme != GROUPSIG_CPY06_CODE ||
     (crl && crl->scheme != GROUPSIG_CPY06_CODE)) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(crl_trap = trapdoor_init(trap->scheme))){
    LOG_EINVAL(&logger, __FILE__, "cpy06_reveal", __LINE__, LOGERROR);
    return IERROR;
  }

  /* The tracing trapdoor for the i-th member is the C value computed during join */
  if(!(gml_entry = ((cpy06_gml_entry_t *) gml_get(gml, index)))) {
    return IERROR;
  }

  if(cpy06_trapdoor_copy(trap, (trapdoor_t *) gml_entry->trapdoor) == IERROR) {
    return IERROR;
  }

  /* If we have received a CRL, update it with the "revoked" member */
  if(crl) {

    if(!(crl_entry = cpy06_crl_entry_init())) {
      return IERROR;
    }

    if(cpy06_identity_copy(crl_entry->id, gml_entry->id) == IERROR) {
      cpy06_crl_entry_free(crl_entry);
      return IERROR;
    }

    cpy06_trapdoor_copy(crl_trap, trap);
    crl_entry->trapdoor = crl_trap;

    if(cpy06_crl_insert(crl, crl_entry) == IERROR) {
      cpy06_crl_entry_free(crl_entry);
      return IERROR;
    }

  }

  return IOK;

}

/* reveal.c ends here */
