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
#include "groupsig/ps16/identity.h"

identity_t* ps16_identity_init() {

  identity_t *id;
  ps16_identity_t *ps16_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(ps16_id = (ps16_identity_t *) mem_malloc(sizeof(ps16_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "ps16_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* A PS16 identity is the index pointing to an entry in the GML, we initialize
     it to UINT64_MAX */
  *ps16_id = UINT64_MAX;
  
  id->scheme = GROUPSIG_PS16_CODE;
  id->id = ps16_id;

  return id;

}

int ps16_identity_free(identity_t *id) {

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_identity_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Currently, it is just an uint64_t* */
  mem_free((ps16_identity_t *)id->id); id->id = NULL;
  mem_free(id); id = NULL;

  return IOK;

}

int ps16_identity_copy(identity_t *dst, identity_t *src) {

  if(!dst || dst->scheme != GROUPSIG_PS16_CODE ||
     !src || src->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  *((ps16_identity_t *) dst->id) = *((ps16_identity_t *) src->id);
  
  return IOK;

}

uint8_t ps16_identity_cmp(identity_t *id1, identity_t *id2) {

  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  if(*(uint64_t *) id1->id != *(uint64_t *) id2->id) return 1;

  return 0;

}

char* ps16_identity_to_string(identity_t *id) {

  if(!id || id->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Currently, the PS16 identities are uint64_t's */
  return misc_uint642string(*((ps16_identity_t *)id->id));

}

identity_t* ps16_identity_from_string(char *sid) {

  identity_t *id;
  uint64_t uid;

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "ps16_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(id = ps16_identity_init())) {
    return NULL;
  }

  /* Currently, PS16 identities are uint64_t's */
  errno = 0;
  uid = strtoul(sid, NULL, 10);
  if(errno) {
    ps16_identity_free(id); id = NULL;
    return NULL;
  }

  *((ps16_identity_t *) id->id) = uid;

  return id;

}

/* identity.c ends here */
