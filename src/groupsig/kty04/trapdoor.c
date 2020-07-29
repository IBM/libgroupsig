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

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "groupsig/kty04/trapdoor.h"

trapdoor_t* kty04_trapdoor_init() {

  trapdoor_t *trap;
  kty04_trapdoor_t *kty04_trap;

  if(!(trap = (trapdoor_t *) mem_malloc(sizeof(trapdoor_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_trapdoor_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_trap = (kty04_trapdoor_t *) mem_malloc(sizeof(kty04_trapdoor_t)))) {
    mem_free(trap); trap = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_trapdoor_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* A KTY04 identity is the index pointing to an entry in the GML, we initialize 
     it to UINT64_MAX */
  *kty04_trap = bigz_init();
  
  trap->scheme = GROUPSIG_KTY04_CODE;
  trap->trap = kty04_trap;

  return trap;

}

int kty04_trapdoor_free(trapdoor_t *trap) {

  if(!trap) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_trapdoor_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(trap->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_trapdoor_free", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Currently, it is just an uint64_t* */
  bigz_free(*((kty04_trapdoor_t *) trap->trap));
  mem_free((kty04_trapdoor_t *) trap->trap); trap->trap = NULL;  
  mem_free(trap);

  return IOK;

}

int kty04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bigz_set(*((kty04_trapdoor_t *) dst->trap), *((kty04_trapdoor_t *) src->trap));

  return IOK;

}

char* kty04_trapdoor_to_string(trapdoor_t *trap) {

  if(!trap || trap->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Currently, the KTY04 trapdoors are bigz_t's */
  return bigz_get_str(10, *((kty04_trapdoor_t *)trap->trap));

}

trapdoor_t* kty04_trapdoor_from_string(char *strap) {

  trapdoor_t *trap;

  if(!strap) {
    LOG_EINVAL(&logger, __FILE__, "kty04_trapdoor_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(trap = kty04_trapdoor_init())) {
    return NULL;
  }

  /* Currently, KTY04 identities are bigz_t's */
  if(bigz_set_str(*(kty04_trapdoor_t *) trap->trap, strap, 10) == IERROR) {
    kty04_trapdoor_free(trap);
    return NULL;
  }

  return trap;

}

/* identity.c ends here */
