/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: identity.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: jue ene 17 11:21:21 2013 (+0100)
 * @version: 
 * Last-Updated: lun ago  5 15:07:24 2013 (+0200)
 *           By: jesus
 *     Update #: 3
 * URL: 
 */
#include <stdlib.h>

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/pbc_ext.h"
#include "groupsig/dl21/identity.h"

identity_t* dl21_identity_init() {

  identity_t *id;
  dl21_identity_t *dl21_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "dl21_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(dl21_id = (dl21_identity_t *) mem_malloc(sizeof(dl21_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "dl21_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  id->scheme = GROUPSIG_DL21_CODE;
  id->id = dl21_id;
  
  return id;

}

int dl21_identity_free(identity_t *id) {

  dl21_identity_t *dl21_id;

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21_identity_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21_id = id->id;
  pbcext_element_G1_free(dl21_id); dl21_id = NULL;
  mem_free(id);

  return IOK;

}

int dl21_identity_copy(identity_t *dst, identity_t *src) {

  dl21_identity_t *dl21_srcid, *dl21_dstid;
  
  if(!dst || dst->scheme != GROUPSIG_DL21_CODE ||
     !src || src->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21_srcid = src->id;
  dl21_dstid = dst->id;
  
  if(!(dl21_dstid = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_set(dl21_dstid, dl21_srcid) == IERROR) return IERROR;
  
  return IOK;

}

uint8_t dl21_identity_cmp(identity_t *id1, identity_t *id2) {

  dl21_identity_t *dl21_id1, *dl21_id2;
  
  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  dl21_id1 = id1->id;
  dl21_id2 = id2->id;

  return pbcext_element_G1_cmp(dl21_id1, dl21_id2);

}

char* dl21_identity_to_string(identity_t *id) {

  dl21_identity_t *dl21_id;
  char *s;
  
  if(!id || id->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  dl21_id = id->id;
  s = pbcext_element_G1_to_b64(dl21_id);

  return s;

}

identity_t* dl21_identity_from_string(char *sid) {

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "dl21_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* identity.c ends here */
