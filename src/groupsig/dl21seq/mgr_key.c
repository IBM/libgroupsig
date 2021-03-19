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
 * @file: mgr_key.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: mié may  9 18:44:54 2012 (+0200)
 * @version: 
 * Last-Updated: lun ago  5 15:10:46 2013 (+0200)
 *           By: jesus
 *     Update #: 4
 * URL: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "dl21seq.h"
#include "groupsig/dl21seq/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

groupsig_key_t* dl21seq_mgr_key_init() {

    groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (dl21seq_mgr_key_t *) mem_malloc(sizeof(dl21seq_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_DL21SEQ_CODE;

  return key;

}

int dl21seq_mgr_key_free(groupsig_key_t *key) {

  dl21seq_mgr_key_t *dl21seq_key;
  
 if(key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    dl21seq_key = key->key;
    pbcext_element_Fr_free(dl21seq_key->isk); dl21seq_key->isk = NULL;
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int dl21seq_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  dl21seq_mgr_key_t *dl21seq_dst, *dl21seq_src;

  if(!dst || dst->scheme != GROUPSIG_DL21SEQ_CODE ||
     !src || src->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21seq_dst = dst->key;
  dl21seq_src = src->key;

  /* Copy the elements */
  if(!(dl21seq_dst->isk = pbcext_element_Fr_init())) return IERROR;
  if(pbcext_element_Fr_set(dl21seq_dst->isk, dl21seq_src->isk) == IERROR) {
    pbcext_element_Fr_free(dl21seq_dst->isk); dl21seq_dst->isk = NULL;
    return IERROR;
  }

  return IOK;

}

int dl21seq_mgr_key_get_size(groupsig_key_t *key) {

  dl21seq_mgr_key_t *dl21seq_key;
  uint64_t sisk;
  int size;

  if(!key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  dl21seq_key = key->key;
  sisk = 0;

  if (dl21seq_key->isk) { if(pbcext_element_Fr_byte_size(&sisk) == IERROR) return -1; }

  if ((int) sisk + sizeof(int)*1+2 > INT_MAX) return -1;
  size = (int) sisk + sizeof(int)*1+2;

  return size;

}

int dl21seq_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  dl21seq_mgr_key_t *dl21seq_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21seq_key = key->key;

  if ((_size = dl21seq_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_DL21SEQ_CODE */
  _bytes[ctr++] = GROUPSIG_DL21SEQ_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump isk */
  if(dl21seq_key->isk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_key->isk) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mgr_key_export);
  }

  *size = ctr;

 dl21seq_mgr_key_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;
  
}

groupsig_key_t* dl21seq_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  dl21seq_mgr_key_t *dl21seq_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;  
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = dl21seq_mgr_key_init())) {
    return NULL;
  }
  dl21seq_key = key->key;    

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mgr_key_import);
  }  

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mgr_key_import);
  }    

  /* Get isk */
  if(!(dl21seq_key->isk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(dl21seq_key->isk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(dl21seq_key->isk); dl21seq_key->isk = NULL;
  } else {
    ctr += len;
  }

 dl21seq_mgr_key_import_end:
  
  if(rc == IERROR && key) { dl21seq_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* dl21seq_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
