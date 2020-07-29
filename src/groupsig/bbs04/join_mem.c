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

#include "bbs04.h"
#include "groupsig/bbs04/grp_key.h"
#include "groupsig/bbs04/mem_key.h"
#include "bigz.h"
#include "sys/mem.h"

/** 
 * @fn int bbs04_join_mem(groupsig_key_t *memkey, groupsig_key_t *grpkey)
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
int bbs04_join_mem(message_t **mout, groupsig_key_t *memkey,
		   int seq, message_t *min, groupsig_key_t *grpkey) {

  groupsig_key_t *_memkey;
  int rc;
  
  if(!memkey || memkey->scheme != GROUPSIG_BBS04_CODE ||
     !min || seq != 1) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  _memkey = NULL;
  rc = IOK;

  /* This is mainly an utility function to keep uniformity across schemes: 
     Just import the memkey from the received message and copy it into the
     provided memkey*/
  if(!(_memkey = bbs04_mem_key_import(min->bytes, min->length)))
    GOTOENDRC(IERROR, bbs04_join_mem);

  if(bbs04_mem_key_copy(memkey, _memkey) == IERROR)
    GOTOENDRC(IERROR, bbs04_join_mem);

 bbs04_join_mem_end:

  bbs04_mem_key_free(_memkey); _memkey = NULL;
  
  return rc;

}

/* join_mem.c ends here */
