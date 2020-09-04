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
#include "groupsig/bbs04/trapdoor.h"

trapdoor_t* bbs04_trapdoor_init() {
  
  trapdoor_t *trap;
  bbs04_trapdoor_t *bbs04_trap;
  
  if(!(trap = (trapdoor_t *) mem_malloc(sizeof(trapdoor_t)))) {
    return NULL;
  }

  if(!(bbs04_trap = (bbs04_trapdoor_t *) mem_malloc(sizeof(bbs04_trapdoor_t)))) {
    mem_free(trap); trap = NULL;
    return NULL;
  }
  
  /* BBS04 does not implement tracing */
  bbs04_trap->trace = NULL;
  
  /* The bbs04_trap->open field is of type element_t (pbc library) and the
     pairing is necessary to initialize it, hence, it must be initialized
     and set in the join_mgr function. */
  
  trap->scheme = GROUPSIG_BBS04_CODE;
  trap->trap = bbs04_trap;
  
  return trap;
  
}

int bbs04_trapdoor_free(trapdoor_t *trap) {
  
  bbs04_trapdoor_t *bbs04_trap;
  
  if(!trap || trap->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_trapdoor_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(trap->trap) {
    bbs04_trap = trap->trap;
    pbcext_element_G1_free(bbs04_trap->open);
    mem_free(bbs04_trap); bbs04_trap = NULL;
  }
  
  mem_free(trap); trap = NULL;
  
  return IOK;
  
}

int bbs04_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {
  
  if(!dst || dst->scheme != GROUPSIG_BBS04_CODE ||
     !src || src->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(((bbs04_trapdoor_t *) dst->trap)->open = pbcext_element_G1_init()))
    return IERROR;

  if(pbcext_element_G1_set(((bbs04_trapdoor_t *) dst->trap)->open, 
			   ((bbs04_trapdoor_t *) src->trap)->open) == IERROR) {
    pbcext_element_G1_free(((bbs04_trapdoor_t *) dst->trap)->open);
    ((bbs04_trapdoor_t *) dst->trap)->open = NULL;
    return IERROR;
  }
  
  return IOK;

}

char* bbs04_trapdoor_to_string(trapdoor_t *trap) {
  
  char *str;
  
  if(!trap || trap->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  /* BBS04 only has open trapdoors, with type bigz */
  if(!(str = pbcext_element_G1_to_b64(((bbs04_trapdoor_t *)trap->trap)->open))) {
    return NULL;
  }
  
  return str;
  
}

trapdoor_t* bbs04_trapdoor_from_string(char *strap) {
  
  trapdoor_t *trap;
  
  if(!strap) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_trapdoor_from_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(!(trap = bbs04_trapdoor_init())) {
    return NULL;
  }

  /* Open trapdoors are the A elements of the member keys */
  if(!(((bbs04_trapdoor_t *) trap->trap)->open = pbcext_element_G1_init()))
    return NULL;
  if(pbcext_element_G1_from_b64(((bbs04_trapdoor_t *) trap->trap)->open, strap) == IERROR) {
    bbs04_trapdoor_free(trap); trap = NULL;
    return NULL;
  }
  
  return trap;
  
}

int bbs04_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2) {
  
  if(!t1 || t1->scheme != GROUPSIG_BBS04_CODE ||
     !t2 || t2->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_trapdoor_cmp", __LINE__, LOGERROR);
    return IERROR;
  }

  return pbcext_element_G1_cmp(((bbs04_trapdoor_t *)t1->trap)->open, 
			       ((bbs04_trapdoor_t *)t2->trap)->open);

}

/* identity.c ends here */
