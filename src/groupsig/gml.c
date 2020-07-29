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
#include "gml.h"
#include "gml_handles.h"
#include "logger.h"

const gml_handle_t* gml_handle_from_code(uint8_t code) {

  int i;
  
  for(i=0; i<GML_HANDLES_N; i++) {
    if(GML_HANDLES[i]->scheme == code)
      return GML_HANDLES[i];
  }

  return NULL;

}

gml_t* gml_init(uint8_t scheme) {

  const gml_handle_t *gh;

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_init", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }
  
  return gh->gml_init();  

}

int gml_free(gml_t *gml) {

  const gml_handle_t *gh;

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_free", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }
  
  return gh->gml_free(gml);  

}

int gml_insert(gml_t *gml, void *entry) {

  const gml_handle_t *gh;

  if(!gml || !entry) {
    LOG_EINVAL(&logger, __FILE__, "gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_insert", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->gml_insert(gml, entry);

}

int gml_remove(gml_t *gml, uint64_t index) {

  const gml_handle_t *gh;

  if(!gml) {
    LOG_EINVAL(&logger, __FILE__, "gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_remove", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->gml_remove(gml, index);

}

void* gml_get(gml_t *gml, uint64_t index) {

  const gml_handle_t *gh;

  if(!gml) {
    LOG_EINVAL(&logger, __FILE__, "gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_get", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->gml_get(gml, index);
    
}

gml_t* gml_import(uint8_t code, gml_format_t format, void *source) {

  const gml_handle_t *gh;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(code))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->gml_import(format, source);

}

int gml_export(gml_t *gml, void *dst, gml_format_t format) {

  const gml_handle_t *gh;

  if(!gml || !dst) {
    LOG_EINVAL(&logger, __FILE__, "gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->gml_export(gml, dst, format);

}

int gml_export_new_entry(uint8_t scheme, void *entry, void *dst, 
			 gml_format_t format) {

  const gml_handle_t *gh;

  if(!entry || !dst) {
    LOG_EINVAL(&logger, __FILE__, "gml_export_new_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->gml_export_new_entry(entry, dst, format);

}

int gml_compare_entries(int *eq, void *entry1, void *entry2, gml_cmp_entries_f cmp) {

  if(!eq || !entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "gml_compare_entries", __LINE__, LOGERROR);
    return IERROR;
  }

  errno = 0;
  *eq = cmp(entry1, entry2);
  if(errno) {
    LOG_ERRORCODE(&logger, __FILE__, "gml_compare_entries (cmp)", __LINE__, 
		  errno, LOGERROR);
    return IERROR;
  }

  return IOK;

}

/* gml.c ends here */
