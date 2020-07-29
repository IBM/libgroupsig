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
#include "groupsig/bbs04/identity.h"

identity_t* bbs04_identity_init() {

  identity_t *id;
  bbs04_identity_t *bbs04_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(bbs04_id = (bbs04_identity_t *) mem_malloc(sizeof(bbs04_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* A BBS04 identity is the index pointing to an entry in the GML, we initialize
     it to UINT64_MAX */
  *bbs04_id = UINT64_MAX;
  
  id->scheme = GROUPSIG_BBS04_CODE;
  id->id = bbs04_id;

  return id;

}

int bbs04_identity_free(identity_t *id) {

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_identity_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Currently, it is just an uint64_t* */
  mem_free((bbs04_identity_t *)id->id); id->id = NULL;
  mem_free(id); id = NULL;

  return IOK;

}

int bbs04_identity_copy(identity_t *dst, identity_t *src) {

  if(!dst || dst->scheme != GROUPSIG_BBS04_CODE ||
     !src || src->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  *((bbs04_identity_t *) dst->id) = *((bbs04_identity_t *) src->id);
  
  return IOK;

}

uint8_t bbs04_identity_cmp(identity_t *id1, identity_t *id2) {

  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  if(*(uint64_t *) id1->id != *(uint64_t *) id2->id) return 1;

  return 0;

}

char* bbs04_identity_to_string(identity_t *id) {

  if(!id || id->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Currently, the BBS04 identities are uint64_t's */
  return misc_uint642string(*((bbs04_identity_t *)id->id));

}

identity_t* bbs04_identity_from_string(char *sid) {

  identity_t *id;
  uint64_t uid;

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(id = bbs04_identity_init())) {
    return NULL;
  }

  /* Currently, BBS04 identities are uint64_t's */
  errno = 0;
  uid = strtoul(sid, NULL, 10);
  if(errno) {
    bbs04_identity_free(id); id = NULL;
    return NULL;
  }

  *((bbs04_identity_t *) id->id) = uid;

  return id;

}

/* identity.c ends here */
