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
  
  return gh->init();  

}

int gml_free(gml_t *gml) {

  const gml_handle_t *gh;

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_free", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }
  
  return gh->free(gml);  

}

int gml_insert(gml_t *gml, gml_entry_t *entry) {

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

  return gh->insert(gml, entry);

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

  return gh->remove(gml, index);

}

gml_entry_t* gml_get(gml_t *gml, uint64_t index) {

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

  return gh->get(gml, index);
    
}

int gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  const gml_handle_t *gh;

  if(!bytes || !size || !gml) {
    LOG_EINVAL(&logger, __FILE__, "gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(gml->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_export", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->gexport(bytes, size, gml);

}

gml_t* gml_import(uint8_t code, byte_t *bytes, uint32_t size) {

  const gml_handle_t *gh;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(code))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->gimport(bytes, size);

}

gml_entry_t* gml_entry_init(uint8_t code) {

  const gml_handle_t *gh;

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(code))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->entry_init();
  
}

int gml_entry_free(gml_entry_t *entry) {

  const gml_handle_t *gh;  

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(entry->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->entry_free(entry);  

}

int gml_entry_get_size(gml_entry_t *entry) {

  const gml_handle_t *gh;    

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(entry->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->entry_get_size(entry);

}

int gml_entry_export(byte_t **bytes, uint32_t *size, gml_entry_t *entry) {

  const gml_handle_t *gh;    

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(entry->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return IERROR;
  }

  return gh->entry_export(bytes, size, entry);

}

gml_entry_t* gml_entry_import(uint8_t code, byte_t *bytes, uint32_t size) {

  const gml_handle_t *gh;    

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(code))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->entry_import(bytes, size);
  
}

char* gml_entry_to_string(gml_entry_t *entry) {

  const gml_handle_t *gh;  

  /* Get the GML handles from the code */
  if(!(gh = gml_handle_from_code(entry->scheme))) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gml_import", __LINE__, 
		   "Unsupported scheme.", LOGERROR);
    return NULL;
  }

  return gh->entry_to_string(entry);

}

/* gml.c ends here */
