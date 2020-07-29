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
#include <errno.h>
#include <stdlib.h>

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mem_key.h"
#include "bigz.h"
#include "sys/mem.h"

/** 
 * @fn int cpy06_join_mem(groupsig_key_t **memkey, groupsig_key_t *grpkey)
 * @brief Member side join procedure.
 * 
 * The original proposal does not include a "join" procedure. Instead, it is the
 * private-key issuer generates and distributes the member keys, and requires a
 * predefined group size. We adopt this approach to allow dynamic addition of group
 * members.
 *
 * @param[in,out] memkey Will be set to the produced member key.
 * @param[in] grpkey The group key.
 * 
 * @return IOK or IERROR.
 */
/* @TODO This function still follows the old variable structure for join and 
   I am just changing the interface to remove compiler complaints. But this 
   breaks the functionality! Fix! */
int cpy06_join_mem(void **mout, groupsig_key_t *memkey,
		   int seq, void *min, groupsig_key_t *grpkey) {

  cpy06_sysenv_t *cpy06_sysenv;
  cpy06_mem_key_t *cpy06_memkey;
  cpy06_grp_key_t *cpy06_grpkey;

  if(!mout || !memkey || memkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_sysenv = (cpy06_sysenv_t*) sysenv->data;
  cpy06_memkey = (cpy06_mem_key_t *) memkey->key;
  cpy06_grpkey = (cpy06_grp_key_t *) grpkey->key;
  cpy06_sysenv = sysenv->data;

  /** @todo A provably secure two party computation for adaptive chosing of 
      random powers should be executed here (see KTY04). */  
  /* x \in_R Z^*_p */
  element_init_Zr(cpy06_memkey->x, cpy06_sysenv->pairing);
  element_random(cpy06_memkey->x);

  /* By convention here, we will set t and A to 0 to mark that they have not
     been set... (@todo is this a mathematical stupidity?) 
     NOTE: this is needed by some external applications (e.g. caduceus)
  */
  
  element_init_Zr(cpy06_memkey->t, cpy06_sysenv->pairing);
  element_set0(cpy06_memkey->t);
  element_init_G1(cpy06_memkey->A, cpy06_sysenv->pairing);
  element_set0(cpy06_memkey->A);
  
  return IOK;

}

/* join.c ends here */
