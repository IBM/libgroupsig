/*                               -*- Mode: C -*- 
 * @file: message.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: mié jul 18 22:16:54 2012 (+0200)
 * @version: 
 * Last-Updated: Fri Jun  7 09:04:11 2013 (-0400)
 *           By: jesus
 *     Update #: 69
 * URL: 
 */

#include <stdlib.h>
#include <stdint.h>

#include "logger.h"
#include "message.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"
#include "misc/mjson.h"

message_t* message_init() {
  
  message_t *msg;

  if(!(msg = (message_t *) malloc(sizeof(message_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  msg->bytes = NULL;
  msg->length = 0;

  return msg;
  
}

message_t* message_from_string(char *str) {
  
  message_t *msg;
  
  if(!str) {
    LOG_EINVAL(&logger, __FILE__, "message_from_str", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(msg = message_init()))
    return NULL;
  
  if(message_set_bytes_from_string(msg, str) == IERROR) {
    message_free(msg); msg = NULL;
    return NULL;
  }
  
  return msg;
  
}

message_t* message_from_bytes(byte_t *bytes,
			      uint64_t length) {
  
  message_t *msg;
  
  if(!bytes || !length) {
    LOG_EINVAL(&logger, __FILE__, "message_from_bytes", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(!(msg = message_init()))
    return NULL;

  if(!(msg->bytes = (byte_t *) mem_malloc(sizeof(byte_t)*length))) {
    message_free(msg); msg = NULL;
    return NULL;
  }
 
  memcpy(msg->bytes, bytes, length);
  msg->length = length;
  
  return msg;
  
}

int message_free(message_t *msg) {
  
  if(!msg) {
    LOG_EINVAL_MSG(&logger, __FILE__, "message_free", __LINE__, 
                   "Nothing to free.", LOGWARN);
    return IERROR;
  }
    
  if(msg->bytes) { free(msg->bytes); msg->bytes = NULL; }

  free(msg); msg = NULL;
  
  return IOK;
  
}

int message_set_bytes(message_t *msg, byte_t *bytes, uint64_t length) {

  if(!msg || !bytes || !length) {
    LOG_EINVAL(&logger, __FILE__, "message_set_bytes", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(msg->bytes = (byte_t *) malloc(sizeof(byte_t)*length))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_set_bytes", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  memcpy(msg->bytes, bytes, length);
  msg->length = length;

  return IOK;

}

int message_set_bytes_from_string(message_t *msg, char *string) {

  if(!msg || !string) {
    LOG_EINVAL(&logger, __FILE__, "message_set_bytes_from_string",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(msg->bytes = (byte_t *) strdup(string))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_set_bytes_from_string", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  msg->length = strlen(string);

  return IOK;

}

int message_copy(message_t *dst, message_t *src) {

  if(!dst || !src) {
    LOG_EINVAL(&logger, __FILE__, "message_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(dst->bytes = (byte_t *) malloc(sizeof(byte_t*)*(src->length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_copy", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  memset(dst->bytes, 0, src->length+1);

  memcpy(dst->bytes, src->bytes, src->length);
  dst->length = src->length;

  return IOK;

}

char* message_to_string(message_t *msg) {

  char *smsg;
  
  if(!msg) {
    LOG_EINVAL(&logger, __FILE__, "message_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(smsg = (char *) malloc(sizeof(char)*(msg->length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_to_string", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  memset(smsg, 0, (msg->length+1)*sizeof(char));

  /* WARNING! Note that this string may not be printable! */
  sprintf(smsg, "%s", (char *) msg->bytes);

  return smsg;

}

char* message_to_base64(message_t *msg) {

  if(!msg) {
    LOG_EINVAL(&logger, __FILE__, "message_to_base64", __LINE__, LOGERROR);
    return NULL;
  }

  return base64_encode(msg->bytes, msg->length, 0);

}

message_t* message_from_base64(char *b64) {

  message_t *msg;
  byte_t *bytes;
  uint64_t len;
  
  if (!b64) {
    LOG_EINVAL(&logger, __FILE__, "message_from_base64", __LINE__, LOGERROR);
    return NULL;    
  }

  if(!(bytes = base64_decode(b64, &len))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_from_base64", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  if(!(msg = message_from_bytes(bytes, len))) {
    LOG_ERRORCODE(&logger, __FILE__, "message_from_base64", __LINE__, errno,
		  LOGERROR);
    return NULL; 
  }

  return msg;

}

int message_json_get_key(char **value, message_t *msg, char *key) {

  char *_val;

  if (!value || !msg || !key) {
    LOG_EINVAL(&logger, __FILE__, "message_get_key", __LINE__, LOGERROR);
    return IERROR;
  }

  /* The bytes field must be a valid JSON object. Check it. */
  if(mjson((char *) msg->bytes,
	   msg->length,
	   NULL,
	   NULL) == MJSON_ERROR_INVALID_INPUT) {
    return IERROR;
  }

  if(!(_val = (char *) mem_malloc(sizeof(char)*(msg->length+1)))) {
    return IERROR;
  }

  if (mjson_get_string((char *) msg->bytes,
		       msg->length, key, _val, msg->length) == -1) {
    LOG_EINVAL_MSG(&logger, __FILE__, "message_get_key", __LINE__,
  		   "Error fetching key.", LOGERROR);
    mem_free(_val); _val = NULL;
    return IERROR;
  }

  if (!*value) *value = _val;
  else {
    memcpy(*value, _val, strlen(_val));
    mem_free(_val); _val = NULL;
  }

  return IOK;
    
}

/* message.c ends here */
