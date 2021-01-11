#include <assert.h>
#include <node/node_api.h>
//#include <napi.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "groupsig.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "signature.h"
#include "blindsig.h"
#include "identity.h"
#include "message.h"

#include "base64.h"

#define DECLARE_NAPI_METHOD(name, func) { name, 0, func, 0, 0, 0, napi_default, 0 }

#define NAPI_GET_TYPE(arg, str) {					\
    napi_status status;							\
    napi_valuetype type;						\
    status = napi_typeof(env, arg, &type);				\
    assert(status == napi_ok);						\
    if (type == napi_undefined) memcpy(str, "undefined", strlen("undefined")); \
    else if (type == napi_null) memcpy(str, "null", strlen("null"));	\
    else if (type == napi_boolean) memcpy(str, "boolean", strlen("boolean")); \
    else if (type == napi_number) memcpy(str, "number", strlen("undefined")); \
    else if (type == napi_string) memcpy(str, "string", strlen("string")); \
    else if (type == napi_symbol) memcpy(str, "symbol", strlen("symbol")); \
    else if (type == napi_object) memcpy(str, "object", strlen("object")); \
    else if (type == napi_function) memcpy(str, "function", strlen("function")); \
    else if (type == napi_external) memcpy(str, "external", strlen("external")); \
    else if (type == napi_bigint) memcpy(str, "bigint", strlen("bigint")); \
    else memcpy(str, "unknown", strlen("unknown"));			\
  }									\
    
#define NAPI_GET_ARG_UINT32(env, arg, code) {			\
    napi_status status;						\
    napi_valuetype type;					\
    status = napi_typeof(env, arg, &type);			\
    assert(status == napi_ok);					\
    if (type != napi_number) {					\
      napi_throw_type_error(env, NULL, "Wrong arguments");	\
      return NULL;						\
    }								\
    status = napi_get_value_uint32(env, arg, &code);		\
    assert(status == napi_ok);					\
  }								\

#define NAPI_GET_ARG_INT32(env, arg, code) {			\
    napi_status status;						\
    napi_valuetype type;					\
    status = napi_typeof(env, arg, &type);			\
    assert(status == napi_ok);					\
    if (type != napi_number) {					\
      napi_throw_type_error(env, NULL, "Wrong arguments");	\
      return NULL;						\
    }								\
    status = napi_get_value_int32(env, arg, &code);		\
    assert(status == napi_ok);					\
  }								\

#define NAPI_GET_STRING_UTF8(env, arg, str) {				\
    napi_status status;							\
    napi_valuetype type;						\
    size_t length, result;							\
    status = napi_typeof(env, arg, &type);				\
    assert(status == napi_ok);						\
    if (type != napi_string) {						\
      napi_throw_type_error(env, NULL, "Wrong arguments");		\
      return NULL;							\
    }									\
    status = napi_get_value_string_utf8(env, arg, NULL, 0, &length);	\
    if(!(str = (char *) malloc(sizeof(char)*(length+1)))) {		\
      napi_throw_error(env, NULL, "Internal error");		\
      return NULL;							\
    }									\
    memset(str, 0, length+1);						\
    status = napi_get_value_string_utf8(env, arg, str, length+1, &result);	\
    if (status != napi_ok) { free(str); str = NULL; return NULL; }	\
  }									\

#define NAPI_IS_NULL(env, arg, bp) {		\
    napi_value jsnull;						       \
    if(napi_get_null(env, &jsnull) != napi_ok) {		       \
      napi_throw_type_error(env, "EINVAL", "Could not get NULL.");     \
      return NULL;						       \
    }								       \
    if(napi_strict_equals(env, jsnull, arg, bp) != napi_ok) {		\
      napi_throw_type_error(env, "EINVAL", "Could not compare to null."); \
      return NULL;							\
    }									\
  }									\
    
napi_value gs_hello_world
(
 napi_env env,
 napi_callback_info info)
{
  napi_status status;
  status = groupsig_hello_world();
  assert (status == napi_ok);
  return NULL;
}

napi_value gs_is_supported_scheme
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nb;
  size_t argc;
  uint32_t code;
  uint8_t rc;
  bool b;
  
  argc = 1;
  
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);
  
  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  rc = groupsig_is_supported_scheme((uint8_t) code);
  
  if (!rc) { b = false; }
  else { b = true; }

  status = napi_get_boolean(env, b, &nb);
  assert(status == napi_ok);

  return nb;
  
}

napi_value gs_get_groupsig_from_str
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_t *gs;
  char *str;
  size_t argc;

  argc = 1;
  
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_STRING_UTF8(env, args[0], str);
  gs = (groupsig_t *) groupsig_get_groupsig_from_str(str);
  
  if (!gs) {
    napi_throw_type_error(env, NULL, "Error getting gs handle.");
    return NULL;
  }

  status = napi_create_external(env, gs, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_get_groupsig_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_t *gs;
  uint32_t code;
  size_t argc;

  argc = 1;
  
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);
  
  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
  
  gs = (groupsig_t *) groupsig_get_groupsig_from_code((uint8_t) code);
  
  if (!gs) {
    napi_throw_type_error(env, NULL, "Error getting gs handle.");
    return NULL;
  }

  status = napi_create_external(env, gs, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2], external;
  uint32_t code, seed;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 1 || argc > 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  if (argc > 1) {
    NAPI_GET_ARG_UINT32(env, args[1], seed);
  } else {
    seed = UINT32_MAX;
  }

  
  /* Run groupsig_init */
  if (groupsig_init((uint8_t) code, (unsigned int) seed) == IERROR) {
    napi_throw_error(env, NULL, "Error initializing groupsig.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_clear
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  if (groupsig_clear(code) == IERROR) {
    napi_throw_error(env, NULL, "Error initializing groupsig.");
    return NULL;
  }
    
  return NULL;
  
}

napi_value gs_has_gml
(
 napi_env env,
 napi_callback_info info
 ) {

  groupsig_t *gs;
  napi_status status;
  napi_value args[1], has_gml;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }  

  if(!(gs = (groupsig_t *) groupsig_get_groupsig_from_code((uint8_t) code))) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;    
  }

  status = napi_create_uint32(env, (uint32_t) gs->desc->has_gml, &has_gml);
  assert (status == napi_ok);

  return has_gml;
  
}

napi_value gs_has_open_proof
(
 napi_env env,
 napi_callback_info info
 ) {

  groupsig_t *gs;
  napi_status status;
  napi_value args[1], has_open_proof;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }  

  if(!(gs = (groupsig_t *) groupsig_get_groupsig_from_code((uint8_t) code))) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;    
  }

  status = napi_create_uint32(env,
			      (uint32_t) gs->desc->has_open_proof,
			      &has_open_proof);
  assert (status == napi_ok);

  return has_open_proof;
  
}

napi_value gs_setup
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[4];
  groupsig_key_t *grpkey, *mgrkey;
  gml_t *gml;
  uint32_t code;
  size_t argc;

  argc = 5;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 3 || argc > 5) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get code */
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  /* Get grpkey */
  if (napi_get_value_external(env, args[1], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get mgrkey */
  if (napi_get_value_external(env, args[2], (void **) &mgrkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  gml = NULL;

  /* Get gml */
  if (argc > 3) {
    if (napi_get_value_external(env, args[3], (void **) &gml) != napi_ok) { 
      napi_throw_type_error(env, "EINVAL", "Expected external");	       
      return NULL;
    }
  }
    
  /* Run groupsig_setup */
  if (groupsig_setup((uint8_t) code, grpkey, mgrkey, gml) == IERROR) {
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  return NULL;
  
}

napi_value gs_get_joinseq
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nseq;
  uint32_t code;
  uint8_t seq;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_get_joinseq */
  if (groupsig_get_joinseq((uint8_t) code, &seq) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  status = napi_create_uint32(env, (uint32_t) seq, &nseq);
  assert(status == napi_ok);

  return nseq;
  
}

napi_value gs_get_joinstart
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nstart;
  uint32_t code;
  uint8_t start;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_get_joinstart */
  if (groupsig_get_joinstart((uint8_t) code, &start) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  status = napi_create_uint32(env, (uint32_t) start, &nstart);
  assert(status == napi_ok);

  return nstart;
  
}

napi_value gs_join_mem
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[4], external;
  groupsig_key_t *memkey, *grpkey;
  message_t *mout, *min;
  int32_t step;
  size_t argc;
  bool b;

  argc = 4;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 3 && argc != 4) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get step */
  NAPI_GET_ARG_INT32(env, args[0], step);
  
  /* Get memkey */
  if (napi_get_value_external(env, args[1], (void **) &memkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Get grpkey */
  if (napi_get_value_external(env, args[2], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  min = NULL;
  /* Get min */
  if (argc == 4) {

    /* Check if it is null */
    NAPI_IS_NULL(env, args[3], &b);
    
    if(!b) {
      if (napi_get_value_external(env, args[3], (void **) &min) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external");	       
	return NULL;
      }
    }
    
  }
    
  /* Run groupsig_join_mem */
  mout = NULL;  
  if (groupsig_join_mem(&mout, memkey, step, min, grpkey) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  status = napi_create_external(env, mout, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
    
}

napi_value gs_join_mgr
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[5], external;
  groupsig_key_t *mgrkey, *grpkey;
  gml_t *gml;
  message_t *mout, *min;
  int32_t step;
  size_t argc;
  bool b;

  argc = 5;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 3 && argc > 5) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get step */
  NAPI_GET_ARG_INT32(env, args[0], step);

  /* Get mgrkey */
  if (napi_get_value_external(env, args[1], (void **) &mgrkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get grpkey */
  if (napi_get_value_external(env, args[2], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get min */
  min = NULL;
  if (argc >= 4) {

    /* Check if it is null */
    NAPI_IS_NULL(env, args[3], &b);

    if (!b) {
      if (napi_get_value_external(env, args[3], (void **) &min) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external");	       
	return NULL;
      }
    }
    
  }

  /* Check if gml */
  gml = NULL;
  if (argc == 5) {
    if (napi_get_value_external(env, args[4], (void **) &gml) != napi_ok) { 
      napi_throw_type_error(env, "EINVAL", "Expected external");	       
      return NULL;
    }
  }
    
  /* Run groupsig_join_mgr */
  mout = NULL;  
  if (groupsig_join_mgr(&mout, gml, mgrkey, step, min, grpkey) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  status = napi_create_external(env, mout, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
    
}

napi_value gs_sign
(
 napi_env env,
 napi_callback_info info
 ) {
  groupsig_signature_t *sig;
  groupsig_key_t *memkey, *grpkey;
  message_t *msg;
  char *str;
  byte_t *bytes;
  napi_value js_sig, args[5];
  napi_valuetype type;  
  napi_status status; 
  uint32_t seed;
  size_t argc, bytes_length;
  bool isArrayBuff;  

  argc = 4;
  sig = NULL; js_sig = NULL; str = NULL;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert (status == napi_ok);

  if (argc < 3 && argc > 4) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get message */

  /* Check type. It can be a string or an array of bytes */
  status = napi_typeof(env, args[0], &type);
  assert(status == napi_ok);
  if (type == napi_string) {
    NAPI_GET_STRING_UTF8(env, args[0], str);
    msg = message_from_string(str);
  } else if (type == napi_object) {
    isArrayBuff = 0;    
    status = napi_is_arraybuffer(env, args[0], &isArrayBuff);
    assert(status == napi_ok);
    if (isArrayBuff != true)
      napi_throw_error(env, "EINVAL", "Expected an ArrayBuffer");
    bytes = NULL;
    bytes_length = 0;
    napi_get_arraybuffer_info(env, args[0], (void **) &bytes, &bytes_length);
    assert(status == napi_ok);
    msg = message_from_bytes(bytes, bytes_length);
    
  } else {
    napi_throw_error(env, "EINVAL", "Wrong message format.");
    goto gs_sign_end;
  }
  
  if (!msg) {
    napi_throw_error(env, NULL, "Error importing message.");
    goto gs_sign_end;
  }

  /* Get memkey */
  if (napi_get_value_external(env, args[1], (void **) &memkey) != napi_ok) {
    napi_throw_type_error(env, "EINVAL", "Expected external");
    goto gs_sign_end;
  }

  /* Get grpkey */
  if (napi_get_value_external(env, args[2], (void **) &grpkey) != napi_ok) {
    napi_throw_type_error(env, "EINVAL", "Expected external");
    goto gs_sign_end;
  }

  seed = UINT_MAX;
  if (argc == 4) {
    /* Get seed */
    NAPI_GET_ARG_UINT32(env, args[3], seed);
  }

  if(!(sig = groupsig_signature_init(grpkey->scheme))) {
    napi_throw_error(env, NULL, "Internal error.");
    goto gs_sign_end;
  }

  /* Run groupsig_sign */
  if (groupsig_sign(sig, msg, memkey, grpkey, seed) == IERROR) {
    napi_throw_error(env, NULL, "Internal error.");
    goto gs_sign_end;    
  }
  status = napi_create_external(env, sig, NULL, NULL, &js_sig);
  if (status != napi_ok) goto gs_sign_end;

 gs_sign_end:
  if (str) { free(str); str = NULL; }
  if (status != napi_ok) {
    if (sig) { groupsig_signature_free(sig); sig = NULL; }
  }
  return js_sig;
    
}

napi_value gs_verify
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[3], nb;
  napi_valuetype type;  
  groupsig_signature_t *sig;
  groupsig_key_t *grpkey;
  char *str;
  message_t *msg;
  byte_t *bytes;
  size_t argc, result, length, bytes_length;
  uint8_t ok;
  bool b, isArrayBuff;

  str = NULL; argc = 3;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 3) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get signature */
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }

  /* Get message */

  /* Check type. It can be a string or an array of bytes */
  status = napi_typeof(env, args[1], &type);
  assert(status == napi_ok);
  if (type == napi_string) {
    NAPI_GET_STRING_UTF8(env, args[1], str);
    msg = message_from_string(str);      
  } else if (type == napi_object) {
    isArrayBuff = 0;    
    status = napi_is_arraybuffer(env, args[1], &isArrayBuff);
    assert(status == napi_ok);
    if (isArrayBuff != true)
      napi_throw_error(env, "EINVAL", "Expected an ArrayBuffer");
    bytes = NULL;
    bytes_length = 0;
    napi_get_arraybuffer_info(env, args[1], (void **) &bytes, &bytes_length);
    assert(status == napi_ok);
    msg = message_from_bytes(bytes, bytes_length);
    
  } else {
    napi_throw_error(env, "EINVAL", "Wrong message format.");
    return NULL;
  }
  
  if (!msg) {
    napi_throw_error(env, NULL, "Error importing message.");
    free(str); str = NULL;
    return NULL;
  }

  /* Get grpkey */
  if (napi_get_value_external(env, args[2], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    free(str); str = NULL;   
    return NULL;
  }
    
  /* Run groupsig_verify */
  if (groupsig_verify(&ok, sig, msg, grpkey) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    free(str); str = NULL;
    return NULL;
  }

  if (!ok) { b = false; }
  else { b = true; }

  status = napi_get_boolean(env, b, &nb);
  if (status != napi_ok) { free(str); str = NULL; return NULL; }

  return nb;
    
}

napi_value gs_open
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[5], nindex;
  groupsig_signature_t *sig;
  groupsig_key_t *grpkey, *mgrkey;
  groupsig_proof_t *proof;
  uint64_t index;
  crl_t *crl;
  gml_t *gml;
  size_t argc, result;
  uint8_t ok;
  bool b;

  argc = 5;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);
  proof = NULL; crl = NULL; gml = NULL;
  
  if (argc < 3 || argc > 5) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get signature */
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }

  /* Get grpkey */
  if (napi_get_value_external(env, args[1], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }

  /* Get mgrkey */
  if (napi_get_value_external(env, args[2], (void **) &mgrkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }

  /* Get gml */
  if (argc > 3) {

    NAPI_IS_NULL(env, args[3], &b);

    if (!b) {
      if (napi_get_value_external(env, args[3], (void **) &gml) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external");
	return NULL;
      }
    }
    
  }

  /* Get proof */
  if (argc > 4) {

    NAPI_IS_NULL(env, args[4], &b);
    if (!b) {
      if (napi_get_value_external(env, args[4], (void **) &proof) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external");
	return NULL;
      }
    }

  }

  /* Get CRL */
  if (argc > 5) {

    NAPI_IS_NULL(env, args[5], &b);

    if (!b) {
      if (napi_get_value_external(env, args[5], (void **) &crl) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external");
	return NULL;
      }
    }
    
  }

  /* Run groupsig_open */
  if (groupsig_open(&index, proof, crl, sig, grpkey, mgrkey, gml) == IERROR) {
    napi_throw_error(env, NULL, "Internal error.");    
    return NULL;
  }

  status = napi_create_uint32(env, (uint32_t) index, &nindex);
  assert(status == napi_ok);

  return nindex;
    
}

napi_value gs_open_verify
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[4], nb;
  groupsig_signature_t *sig;
  groupsig_key_t *grpkey;
  groupsig_proof_t *proof;
  size_t argc, result;
  uint8_t ok;
  bool b;

  argc = 3;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);
  proof = NULL; sig = NULL; grpkey = NULL;
  
  if (argc != 3) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get proof */
  if (napi_get_value_external(env, args[0], (void **) &proof) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }

  /* Get signature */
  if (napi_get_value_external(env, args[1], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }  

  /* Get grpkey */
  if (napi_get_value_external(env, args[2], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");
    return NULL;
  }
    
  /* Run groupsig_open_verify */
  if (groupsig_open_verify(&ok, proof, sig, grpkey) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if (!ok) { b = false; }
  else { b = true; }

  status = napi_get_boolean(env, b, &nb);
  if (status != napi_ok) return NULL;

  return nb;
    
}

napi_value gs_blind
(
 napi_env env,
 napi_callback_info info
 ) {
  
  groupsig_blindsig_t *bsig;
  groupsig_signature_t *sig;
  groupsig_key_t *bldkey, *grpkey;
  message_t *msg;
  char *str;
  napi_status status;
  napi_value args[4], js_bsig; 
  size_t argc;

  argc = 4;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 4) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get the blinding key */
  if (napi_get_value_external(env, args[0], (void **) &bldkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* We do not allow here uninitialized blinding keys. */
  if (!bldkey) {
    napi_throw_type_error(env, "EINVAL", "Blinding key must not be NULL.");
    return NULL;    
  }

  /* Get the grpkey */
  if (napi_get_value_external(env, args[1], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get the signature */
  if (napi_get_value_external(env, args[2], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get the message */
  NAPI_GET_STRING_UTF8(env, args[3], str);

  msg = message_from_string(str);
  if (!msg) {
    napi_throw_error(env, NULL, "Error importing message.");
    return NULL;
  }

  /* Run groupsig_blind */
  if(!(bsig = groupsig_blindsig_init(grpkey->scheme))) {
    napi_throw_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  if (groupsig_blind(bsig, &bldkey, grpkey, sig, msg) == IERROR) {
    groupsig_blindsig_free(bsig); bsig = NULL;
    return NULL;
  }

  js_bsig = NULL;
  status = napi_create_external(env, bsig, NULL, NULL, &js_bsig);
  if (status != napi_ok) {
    groupsig_blindsig_free(bsig); bsig = NULL;
    return NULL;
  }

  return js_bsig;
    
}

napi_value gs_convert
(
 napi_env env,
 napi_callback_info info
 ) {
  
  groupsig_blindsig_t **csigs, **bsigs;
  groupsig_key_t *bldkey, *grpkey, *mgrkey;
  message_t *msg;
  char *str;
  napi_value args[5], csig, js_csigs, element;
  napi_status status;
  uint32_t n_bsigs, i;
  size_t argc;

  argc = 5;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 4 && argc > 5) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  status = napi_ok;
  csigs = NULL; bsigs = NULL;

  /* Get the blinded signatures */
  status = napi_get_array_length(env, args[0], &n_bsigs);
  assert (status == napi_ok);
  
  bsigs = (groupsig_blindsig_t **) malloc(sizeof(groupsig_blindsig_t *)*n_bsigs);
  if (!bsigs) {
    napi_throw_error(env, NULL, "Internal error.");
    return NULL;
  }

  for (i=0; i<n_bsigs; i++) {
    status = napi_get_element(env, args[0], i, &element);
    if (status != napi_ok) goto gs_convert_end;
    status = napi_get_value_external(env, element, (void **) &bsigs[i]);
    if (status != napi_ok) goto gs_convert_end;
  }

  /* Get the grpkey */
  if (napi_get_value_external(env, args[1], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get the mgrkey */
  if (napi_get_value_external(env, args[2], (void **) &mgrkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  /* Get the blinding key */
  if (napi_get_value_external(env, args[3], (void **) &bldkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (argc == 5) {

    /* Get the message */
    NAPI_GET_STRING_UTF8(env, args[4], str);

    msg = message_from_string(str);
    if (!msg) {
      napi_throw_error(env, NULL, "Error importing message.");
      return NULL;
    }
    
  } else {
    msg = NULL;
  }

  /* Create an array of n_bsigs converted signatures */
  csigs = (groupsig_blindsig_t **) malloc(sizeof(groupsig_blindsig_t *)*n_bsigs);
  if (!csigs) {
    napi_throw_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  for (i=0; i < n_bsigs; i++) {
    if(!(csigs[i] = groupsig_blindsig_init(grpkey->scheme)))
      goto gs_convert_end;
  }

  /* Run groupsig_convert */
  if (groupsig_convert(csigs, bsigs, n_bsigs, grpkey,
		       mgrkey, bldkey, msg) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    goto gs_convert_end;
  }

  /* Prepare the return array */
  js_csigs = NULL;
  status = napi_create_array_with_length(env, n_bsigs, &js_csigs);
  if (status != napi_ok) goto gs_convert_end;

  for (i=0; i < n_bsigs; i++) {

    /* @TODO napi_finalizer? */
    status = napi_create_external(env, csigs[i], NULL, NULL, &csig);
    if (status != napi_ok) goto gs_convert_end;
    
    status = napi_set_element(env, js_csigs, i, csig);
    if (status != napi_ok) goto gs_convert_end;

  }

 gs_convert_end:

  if (csigs) { free(csigs); csigs = NULL; }
  if (bsigs) { free(bsigs); bsigs = NULL; }
  if (status != napi_ok) return NULL;
  
  return js_csigs;
    
}

napi_value gs_unblind
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[5], js_nym;
  identity_t *nym;
  groupsig_blindsig_t *bsig;
  groupsig_signature_t *sig;
  groupsig_key_t *bldkey, *grpkey;
  message_t *msg;
  size_t argc;
  bool b;

  argc = 5;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);
  
  if (argc < 3 || argc > 5) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  grpkey = NULL; sig = NULL;

  /* Get the blind signature */
  if (napi_get_value_external(env, args[0], (void **) &bsig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external1");	       
    return NULL;
  }
  
  /* Get the blinding key */
  if (napi_get_value_external(env, args[1], (void **) &bldkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external2");	       
    return NULL;
  }

  /* Get the message */
  if (napi_get_value_external(env, args[2], (void **) &msg) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external3");	       
    return NULL;
  }
   
  /* Get the signature */
  if (argc > 3) {

    NAPI_IS_NULL(env, args[3], &b);

    if (!b) {
      if (napi_get_value_external(env, args[3], (void **) &sig) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external4");	       
	return NULL;
      }
    }
  }

  /* Get the group key */
  if (argc > 4) {

    NAPI_IS_NULL(env, args[4], &b);

    if (!b) {    
      if (napi_get_value_external(env, args[4], (void **) &grpkey) != napi_ok) { 
	napi_throw_type_error(env, "EINVAL", "Expected external5");	       
	return NULL;
      }
    }

  }
  
  /* Run groupsig_unblind */
  if(!(nym = identity_init(bldkey->scheme))) {
      napi_throw_error(env, NULL, "Internal error.");	       
      return NULL;
  }
  
  if (groupsig_unblind(nym, sig, bsig, grpkey, bldkey, msg) == IERROR) {
      napi_throw_error(env, NULL, "Internal error.");
      message_free(msg); msg = NULL;
      identity_free(nym); nym = NULL;
      return NULL;
  }
  
  status = napi_create_external(env, nym, NULL, NULL, &js_nym);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Internal error.");
    message_free(msg); msg = NULL;
    identity_free(nym); nym = NULL;
    return NULL;
  }
  
  return js_nym;
    
}

napi_value gs_get_code_from_str
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], ncode;
  char *str;
  uint8_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get the name */
  NAPI_GET_STRING_UTF8(env, args[0], str);
    
  /* Get the code */
  if (groupsig_get_code_from_str(&code, str) == IERROR)  {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  /* Convert the code to NAPI format */
  status = napi_create_int32(env, code, &ncode);
  assert(status == napi_ok);

  return ncode;  
    
}

/****** grp_key.h functions ******/

napi_value gs_grp_key_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  grp_key_handle_t *gkh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_grp_key_handle_from_code */
  gkh = (grp_key_handle_t *) groupsig_grp_key_handle_from_code((uint8_t) code);
  
  if (!gkh) {
    napi_throw_type_error(env, NULL, "Error getting group key handle.");
    return NULL;
  }

  status = napi_create_external(env, gkh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_grp_key_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_key_t *key;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_grp_key_handle_from_code */
  key = groupsig_grp_key_init((uint8_t) code);
  
  if (!key) {
    napi_throw_error(env, NULL, "Error initializing group key.");
    return NULL;
  }

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_grp_key_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_key_t *key;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_grp_key_free(key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_grp_key_copy
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2];
  groupsig_key_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_grp_key_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_grp_key_get_size
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nsize;
  groupsig_key_t *key;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_grp_key_get_size(key);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;
  
}

napi_value gs_grp_key_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  char *str;
  byte_t *bytes;
  uint64_t size;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_grp_key_export(&bytes, (uint32_t *) &size, key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result; 
  
}

napi_value gs_grp_key_import
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_key_t *key;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  key = groupsig_grp_key_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!key) {
    napi_throw_error(env, NULL, "Error importing key.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_grp_key_to_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_grp_key_to_string(key);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

/****** mgr_key.h functions ******/

napi_value gs_mgr_key_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  mgr_key_handle_t *gkh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_mgr_key_handle_from_code */
  gkh = (mgr_key_handle_t *) groupsig_mgr_key_handle_from_code((uint8_t) code);
  
  if (!gkh) {
    napi_throw_error(env, NULL, "Error getting group key handle.");
    return NULL;
  }

  status = napi_create_external(env, gkh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_mgr_key_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_key_t *key;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_mgr_key_handle_from_code */
  key = groupsig_mgr_key_init((uint8_t) code);
  
  if (!key) {
    napi_throw_error(env, NULL, "Error initializing manager key.");
    return NULL;
  }

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_mgr_key_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_key_t *key;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_mgr_key_free(key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_mgr_key_copy
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2];
  groupsig_key_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_mgr_key_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_mgr_key_get_size
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nsize;
  groupsig_key_t *key;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_mgr_key_get_size(key);
  assert (!errno);

    /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;
  
}

napi_value gs_mgr_key_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  byte_t *bytes;
  char *str;
  uint64_t size;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_mgr_key_export(&bytes, (uint32_t *) &size, key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_mgr_key_import
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_key_t *key;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  } 

  key = groupsig_mgr_key_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!key) {
    napi_throw_error(env, NULL, "Error importing key.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_mgr_key_to_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_mgr_key_to_string(key);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

/****** mem_key.h functions ******/

napi_value gs_mem_key_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  mem_key_handle_t *gkh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_mem_key_handle_from_code */
  gkh = (mem_key_handle_t *) groupsig_mem_key_handle_from_code((uint8_t) code);
  
  if (!gkh) {
    napi_throw_error(env, NULL, "Error getting group key handle.");
    return NULL;
  }

  status = napi_create_external(env, gkh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_mem_key_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_key_t *key;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_mem_key_handle_from_code */
  key = groupsig_mem_key_init((uint8_t) code);
  
  if (!key) {
    napi_throw_error(env, NULL, "Error initializing member key.");
    return NULL;
  }

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_mem_key_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_key_t *key;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_mem_key_free(key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_mem_key_copy
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2];
  groupsig_key_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_mem_key_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_mem_key_get_size
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nsize;
  groupsig_key_t *key;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_mem_key_get_size(key);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;  
  
}

napi_value gs_mem_key_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_mem_key_export(&bytes, (uint32_t *) &size, key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);
  
  return result;
  
}

napi_value gs_mem_key_import
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_key_t *key;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  } 
  
  key = groupsig_mem_key_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!key) {
    napi_throw_error(env, NULL, "Error importing key.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_mem_key_to_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_mem_key_to_string(key);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

/****** bld_key.h functions ******/

napi_value gs_bld_key_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  bld_key_handle_t *gkh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_bld_key_handle_from_code */
  gkh = (bld_key_handle_t *) groupsig_bld_key_handle_from_code((uint8_t) code);
  
  if (!gkh) {
    napi_throw_error(env, NULL, "Error getting group key handle.");
    return NULL;
  }

  status = napi_create_external(env, gkh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_bld_key_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_key_t *key;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_bld_key_handle_from_code */
  key = groupsig_bld_key_init((uint8_t) code);
  
  if (!key) {
    napi_throw_error(env, NULL, "Error initializing blinding key.");
    return NULL;
  }

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_bld_key_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_key_t *key;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_bld_key_free(key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_bld_key_random
(
 napi_env env,
 napi_callback_info info
 ) {
  
  groupsig_key_t *bldkey, *grpkey;
  napi_status status;
  napi_value args[1], js_bldkey;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  if (napi_get_value_external(env, args[0], (void **) &grpkey) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if(!(bldkey = groupsig_bld_key_random(grpkey->scheme, grpkey))) {
    napi_throw_error(env, NULL, "Internal error.");	       
    return NULL;
  }

  js_bldkey = NULL;
  status = napi_create_external(env, bldkey, NULL, NULL, &js_bldkey);
  if (status != napi_ok) {
    groupsig_bld_key_free(bldkey); bldkey = NULL;
  }
  
  return js_bldkey;
  
}

napi_value gs_bld_key_copy
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2];
  groupsig_key_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_bld_key_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_bld_key_get_size
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], nsize;
  groupsig_key_t *key;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_bld_key_get_size(key);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;  
  
}

napi_value gs_bld_key_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  byte_t *bytes;
  char *str;
  uint32_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_bld_key_export(&bytes, (uint32_t *) &size, key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_bld_key_export_pub
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_bld_key_export_pub(&bytes, (uint32_t *) &size, key) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_bld_key_import
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_key_t *key;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  key = groupsig_bld_key_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!key) {
    napi_throw_error(env, NULL, "Error importing key.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, key, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

napi_value gs_bld_key_to_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_key_t *key;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &key) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_bld_key_to_string(key);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

/****** signature.h ******/

napi_value gs_signature_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_signature_handle_t *gsh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_signature_handle_from_code */
  gsh = (groupsig_signature_handle_t *) groupsig_signature_handle_from_code((uint8_t) code);
  
  if (!gsh) {
    napi_throw_error(env, NULL, "Error getting group signature handle.");
    return NULL;
  }

  status = napi_create_external(env, gsh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_signature_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_signature_t *sig;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_signature_init */
  sig = groupsig_signature_init((uint8_t) code);
  
  if (!sig) {
    napi_throw_error(env, NULL, "Error initializing group signature.");
    return NULL;
  }

  status = napi_create_external(env, sig, NULL, NULL, &external);
  assert (status == napi_ok);
  return external;
  
}

napi_value gs_signature_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_signature_t *sig;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run groupsig_signature_free */
  if (groupsig_signature_free(sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

napi_value gs_signature_get_code
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], scheme;
  groupsig_signature_t *sig;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  status = napi_create_uint32(env, (uint32_t) sig->scheme, &scheme);
  assert (status == napi_ok);

  return scheme;

}

napi_value gs_signature_copy
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2];
  groupsig_signature_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_signature_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_signature_get_size
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], nsize;
  groupsig_signature_t *sig;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_signature_get_size(sig);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;  
  
}


napi_value gs_signature_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_signature_t *sig;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_signature_export(&bytes, (uint32_t *) &size, sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_signature_import
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_signature_t *sig;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  } 
    
  sig = groupsig_signature_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!sig) {
    napi_throw_error(env, NULL, "Error importing sig.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, sig, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;  
  
}

napi_value gs_signature_to_string
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], result;
  groupsig_signature_t *sig;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_signature_to_string(sig);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;  
  
}

/****** proof.h ******/

napi_value gs_proof_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_proof_handle_t *gsh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_proof_handle_from_code */
  gsh = (groupsig_proof_handle_t *) groupsig_proof_handle_from_code((uint8_t) code);
  
  if (!gsh) {
    napi_throw_error(env, NULL, "Error getting group proof handle.");
    return NULL;
  }

  status = napi_create_external(env, gsh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_proof_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_proof_t *proof;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_proof_init */
  proof = groupsig_proof_init((uint8_t) code);
  
  if (!proof) {
    napi_throw_error(env, NULL, "Error initializing group proof.");
    return NULL;
  }

  status = napi_create_external(env, proof, NULL, NULL, &external);
  assert (status == napi_ok);
  return external;
  
}

napi_value gs_proof_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_proof_t *sig;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run groupsig_proof_free */
  if (groupsig_proof_free(sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

/* napi_value gs_proof_copy */
/* ( */
/*  napi_env env, */
/*  napi_callback_info info */
/*  ) { */

/*   napi_status status; */
/*   napi_value args[2]; */
/*   groupsig_proof_t *src, *dst; */
/*   size_t argc; */

/*   argc = 2; */
/*   status = napi_get_cb_info(env, info, &argc, args, NULL, NULL); */
/*   assert(status == napi_ok); */

/*   if (argc != 2) { */
/*     napi_throw_type_error(env, NULL, "Wrong number of arguments"); */
/*     return NULL; */
/*   } */
 
/*   if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) {  */
/*     napi_throw_type_error(env, "EINVAL", "Expected external");	        */
/*     return NULL; */
/*   } */

/*   if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) {  */
/*     napi_throw_type_error(env, "EINVAL", "Expected external");	        */
/*     return NULL; */
/*   } */

/*   if (groupsig_proof_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

/*   return NULL; */
  
/* } */

napi_value gs_proof_get_size
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], nsize;
  groupsig_proof_t *sig;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_proof_get_size(sig);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;  
  
}


napi_value gs_proof_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_proof_t *sig;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_proof_export(&bytes, (uint32_t *) &size, sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_proof_import
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_proof_t *sig;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  } 
    
  sig = groupsig_proof_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!sig) {
    napi_throw_error(env, NULL, "Error importing sig.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, sig, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;  
  
}

napi_value gs_proof_to_string
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], result;
  groupsig_proof_t *sig;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_proof_to_string(sig);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;  
  
}

/****** blindsig.h ******/

napi_value gs_blindsig_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_blindsig_handle_t *gsh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_blindsig_handle_from_code */
  gsh = (groupsig_blindsig_handle_t *) groupsig_blindsig_handle_from_code((uint8_t) code);
  
  if (!gsh) {
    napi_throw_error(env, NULL, "Error getting group blindsig handle.");
    return NULL;
  }

  status = napi_create_external(env, gsh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_blindsig_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  groupsig_blindsig_t *sig;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_blindsig_init */
  sig = groupsig_blindsig_init((uint8_t) code);
  
  if (!sig) {
    napi_throw_error(env, NULL, "Error initializing group blindsig.");
    return NULL;
  }

  status = napi_create_external(env, sig, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_blindsig_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  groupsig_blindsig_t *sig;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run groupsig_blindsig_free */
  if (groupsig_blindsig_free(sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

napi_value gs_blindsig_copy
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2];
  groupsig_blindsig_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (groupsig_blindsig_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_blindsig_get_size
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], nsize;
  groupsig_blindsig_t *sig;
  size_t argc;
  int size;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  size = groupsig_blindsig_get_size(sig);
  assert (!errno);

  /* Convert the size to NAPI format */
  status = napi_create_int32(env, (int32_t) size, &nsize);
  assert(status == napi_ok);

  return nsize;  
  
}

napi_value gs_blindsig_export
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  groupsig_blindsig_t *sig;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (groupsig_blindsig_export(&bytes, (uint32_t *) &size, sig) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }
  free(bytes); bytes = NULL;

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;
  
}

napi_value gs_blindsig_import
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  groupsig_blindsig_t *sig;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
  
  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  sig = groupsig_blindsig_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!sig) {
    napi_throw_error(env, NULL, "Error importing sig.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, sig, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;  
  
}

napi_value gs_blindsig_to_string
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], result;
  groupsig_blindsig_t *sig;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &sig) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = groupsig_blindsig_to_string(sig);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;  
  
}

/****** identity.h ******/

napi_value gs_identity_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  identity_handle_t *gsh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run groupsig_blindsig_handle_from_code */
  gsh = (identity_handle_t *) identity_handle_from_code((uint8_t) code);
  
  if (!gsh) {
    napi_throw_error(env, NULL, "Error getting identity handle.");
    return NULL;
  }

  status = napi_create_external(env, gsh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_identity_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  identity_t *id;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* identity_init actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run identity_init */
  id = identity_init((uint8_t) code);
  
  if (!id) {
    napi_throw_error(env, NULL, "Error initializing identity.");
    return NULL;
  }

  status = napi_create_external(env, id, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_identity_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  identity_t *id;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &id) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run identity_free */
  if (identity_free(id) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

napi_value gs_identity_copy
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2];
  identity_t *src, *dst;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &dst) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &src) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (identity_copy(dst, src) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  return NULL;
  
}

napi_value gs_identity_cmp
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], neq;
  identity_t *id1, *id2;
  size_t argc;
  uint8_t eq;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &id1) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  if (napi_get_value_external(env, args[1], (void **) &id2) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  errno = 0;
  eq = identity_cmp(id1, id2);
  if (errno) {
    napi_throw_type_error(env, NULL, "Identity comparison error.");	       
    return NULL;
  }

  /* Convert the code to NAPI format */
  status = napi_create_int32(env, (int32_t) eq, &neq);
  assert(status == napi_ok);

  return neq;
  
}

napi_value gs_identity_to_string
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[1], result;
  identity_t *id;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &id) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = identity_to_string(id);

  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;  
  
}

napi_value gs_identity_from_string
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], external;
  identity_t *id;
  char *dst;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* identity_from_string actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], dst);

  id = identity_from_string(code, dst);

  if (!id) {
    napi_throw_error(env, NULL, "Error initializing identity.");
    return NULL;
  }

  status = napi_create_external(env, id, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
    
}

/****** gml.h ******/

napi_value gs_gml_handle_from_code
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  gml_handle_t *gsh;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run gml_handle_from_code */
  gsh = (gml_handle_t *) gml_handle_from_code((uint8_t) code);
  
  if (!gsh) {
    napi_throw_error(env, NULL, "Error getting group gml handle.");
    return NULL;
  }

  status = napi_create_external(env, gsh, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_gml_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  gml_t *gml;
  uint32_t code;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }
    
  /* Run gml_init */
  gml = gml_init((uint8_t) code);
  
  if (!gml) {
    napi_throw_error(env, NULL, "Error initializing group gml.");
    return NULL;
  }

  status = napi_create_external(env, gml, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_gml_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  gml_t *gml;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &gml) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run gml_free */
  if (gml_free(gml) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

napi_value gs_gml_export
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], result;
  gml_t *gml;
  byte_t *bytes;
  char *str;
  uint64_t size;  
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
 
  if (napi_get_value_external(env, args[0], (void **) &gml) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }

  bytes = NULL; size = 0;
  if (gml_export(&bytes, (uint32_t *) &size, gml) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  if(!(str = base64_encode(bytes, size, 0))) {
    napi_throw_type_error(env, NULL, "Internal error");	       
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;  
  
}

napi_value gs_gml_import
(
 napi_env env,
 napi_callback_info info
 ) {

  napi_status status;
  napi_value args[2], external;
  char *src;
  byte_t *bytes;
  gml_t *gml;
  uint64_t size;
  uint32_t code;
  size_t argc;

  argc = 2;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 2) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  NAPI_GET_ARG_UINT32(env, args[0], code);

  /* groupsig_is_supported_scheme actually expects an uint8_t */
  if (code > UINT8_MAX) {
    napi_throw_type_error(env, NULL, "Wrong arguments (overflow)");
    return NULL;
  }

  NAPI_GET_STRING_UTF8(env, args[1], src);

  if(!(bytes = base64_decode(src, &size))) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }

  gml = gml_import((uint8_t ) code, bytes, (uint32_t) size);
  if (!gml) {
    napi_throw_error(env, NULL, "Error importing GML.");
    return NULL;
  }

  free(bytes); bytes = NULL;  

  status = napi_create_external(env, gml, NULL, NULL, &external);
  assert (status == napi_ok);
  
  return external;
  
}

/****** message.h ******/

napi_value gs_message_init
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  message_t *msg;
  size_t argc;

  argc = 0;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 0) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
     
  /* Run message_init */
  msg = message_init();
  
  if (!msg) {
    napi_throw_error(env, NULL, "Error initializing message.");
    return NULL;
  }

  status = napi_create_external(env, msg, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_message_free
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1];
  message_t *msg;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }
  
  if (napi_get_value_external(env, args[0], (void **) &msg) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  /* Run gml_free */
  if (message_free(msg) == IERROR) {
    napi_throw_type_error(env, NULL, "Internal error.");
    return NULL;
  }
  
  return NULL;
  
}

napi_value gs_message_from_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  message_t *msg;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get the string */
  NAPI_GET_STRING_UTF8(env, args[0], str);
    
  /* Run message_from_string */
  msg = message_from_string(str);
  if (!msg) {
    napi_throw_error(env, NULL, "Error initializing message.");
    return NULL;
  }

  status = napi_create_external(env, msg, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_message_to_string
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  message_t *msg;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  if (napi_get_value_external(env, args[0], (void **) &msg) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = message_to_string(msg);
  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;    
  
}

napi_value gs_message_from_stringb64
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], external;
  message_t *msg;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  /* Get the string */
  NAPI_GET_STRING_UTF8(env, args[0], str);
    
  /* Run message_from_string */
  msg = message_from_base64(str);
  if (!msg) {
    napi_throw_error(env, NULL, "Error initializing message.");
    return NULL;
  }

  status = napi_create_external(env, msg, NULL, NULL, &external);
  assert (status == napi_ok);

  return external;
  
}

napi_value gs_message_to_stringb64
(
 napi_env env,
 napi_callback_info info
 ) {
  
  napi_status status;
  napi_value args[1], result;
  message_t *msg;
  char *str;
  size_t argc;

  argc = 1;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != 1) {
    napi_throw_type_error(env, NULL, "Wrong number of arguments");
    return NULL;
  }

  if (napi_get_value_external(env, args[0], (void **) &msg) != napi_ok) { 
    napi_throw_type_error(env, "EINVAL", "Expected external");	       
    return NULL;
  }
  
  str = message_to_base64(msg);
  if (!str) {
    napi_throw_error(env, NULL, "Error getting string.");
    return NULL;
  }

  status = napi_create_string_utf8(env, str, strlen(str), &result);
  assert (status == napi_ok);

  return result;    
  
}

/****************************************************/

napi_value Init
(
 napi_env env,
 napi_value exports
 ) {
  
  napi_status status;

  /****** groupsig.h functions ******/

  /* int groupsig_hello_world(void) */
  napi_property_descriptor desc_gs_hello_world =
    DECLARE_NAPI_METHOD("gs_hello_world", gs_hello_world);
  status = napi_define_properties(env, exports, 1, &desc_gs_hello_world);
  assert(status == napi_ok);

  /* uint8_t groupsig_is_supported_scheme(uint8_t code) */
  napi_property_descriptor desc_gs_is_supported_scheme =
    DECLARE_NAPI_METHOD("gs_is_supported_scheme", gs_is_supported_scheme);
  status = napi_define_properties(env, exports, 1, &desc_gs_is_supported_scheme);
  assert(status == napi_ok);

  /* const groupsig_t* groupsig_get_groupsig_from_str(char *str) */
  napi_property_descriptor desc_gs_get_groupsig_from_str =
    DECLARE_NAPI_METHOD("gs_get_groupsig_from_str", gs_get_groupsig_from_str);
  status = napi_define_properties(env, exports, 1, &desc_gs_get_groupsig_from_str);
  assert(status == napi_ok);

  /* const groupsig_t* groupsig_get_groupsig_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_get_groupsig_from_code =
    DECLARE_NAPI_METHOD("gs_get_groupsig_from_code", gs_get_groupsig_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_get_groupsig_from_code);
  assert(status == napi_ok);
  
  /* groupsig_config_t* groupsig_init(uint8_t scheme, unsigned int seed); */
  napi_property_descriptor desc_gs_init =
    DECLARE_NAPI_METHOD("gs_init", gs_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_init);
  assert(status == napi_ok);

  /* int groupsig_clear(uint8_t code); */
  napi_property_descriptor desc_gs_clear =
    DECLARE_NAPI_METHOD("gs_clear", gs_clear);
  status = napi_define_properties(env, exports, 1, &desc_gs_clear);
  assert(status == napi_ok);

  /* Helper function for checking whether a scheme has a gml; */
  napi_property_descriptor desc_gs_has_gml =
    DECLARE_NAPI_METHOD("gs_has_gml", gs_has_gml);
  status = napi_define_properties(env, exports, 1, &desc_gs_has_gml);
  assert(status == napi_ok);

  /* Helper function for checking whether a scheme has open proofs; */
  napi_property_descriptor desc_gs_has_open_proof =
    DECLARE_NAPI_METHOD("gs_has_open_proof", gs_has_open_proof);
  status = napi_define_properties(env, exports, 1, &desc_gs_has_open_proof);
  assert(status == napi_ok);

  /* /\* int groupsig_sysenv_update(uint8_t code, void *data); *\/ */
  /* napi_property_descriptor desc_gs_sysenv_update = */
  /*   DECLARE_NAPI_METHOD("gs_sysenv_update", gs_sysenv_update); */
  /* status = napi_define_properties(env, exports, 1, &desc_gs_sysenv_update); */
  /* assert(status == napi_ok); */
  
  /* /\* void* groupsig_sysenv_get(uint8_t code); *\/ */
  /* napi_property_descriptor desc_gs_sysenv_get = */
  /*   DECLARE_NAPI_METHOD("gs_sysenv_get", gs_sysenv_get); */
  /* status = napi_define_properties(env, exports, 1, &desc_gs_sysenv_get); */
  /* assert(status == napi_ok); */
  
  /* /\* int groupsig_sysenv_free(uint8_t code); *\/ */
  /* napi_property_descriptor desc_gs_sysenv_free = */
  /*   DECLARE_NAPI_METHOD("gs_sysenv_free", gs_senv_free); */
  /* status = napi_define_properties(env, exports, 1, &desc_gs_sysenv_free); */
  /* assert(status == napi_ok); */

  /* int groupsig_setup(uint8_t code, groupsig_key_t *grpkey, 
     groupsig_key_t *mgrkey, gml_t *gml, groupsig_config_t *config); */
  napi_property_descriptor desc_gs_setup =
    DECLARE_NAPI_METHOD("gs_setup", gs_setup);
  status = napi_define_properties(env, exports, 1, &desc_gs_setup);
  assert(status == napi_ok);  

  /* int groupsig_get_joinseq(uint8_t code, uint8_t *seq); */
  napi_property_descriptor desc_gs_get_joinseq =
    DECLARE_NAPI_METHOD("gs_get_joinseq", gs_get_joinseq);
  status = napi_define_properties(env, exports, 1, &desc_gs_get_joinseq);
  assert(status == napi_ok);

  /* int groupsig_get_joinstart(uint8_t code, uint8_t *start); */
  napi_property_descriptor desc_gs_get_joinstart =
    DECLARE_NAPI_METHOD("gs_get_joinstart", gs_get_joinstart);
  status = napi_define_properties(env, exports, 1, &desc_gs_get_joinstart);
  assert(status == napi_ok);

  /* int groupsig_join_mem(void **mout, groupsig_key_t *memkey, */
  /* int seq, void *min, groupsig_key_t *grpkey); */
  napi_property_descriptor desc_gs_join_mem =
    DECLARE_NAPI_METHOD("gs_join_mem", gs_join_mem);
  status = napi_define_properties(env, exports, 1, &desc_gs_join_mem);
  assert(status == napi_ok);

  /* int groupsig_join_mgr(void **mout, gml_t *gml, groupsig_key_t *mgrkey, */
  /* int seq, void *min, groupsig_key_t *grpkey); */
  napi_property_descriptor desc_gs_join_mgr =
    DECLARE_NAPI_METHOD("gs_join_mgr", gs_join_mgr);
  status = napi_define_properties(env, exports, 1, &desc_gs_join_mgr);
  assert(status == napi_ok);

  /* int groupsig_sign(groupsig_signature_t *sig, message_t *msg,  */
  /* groupsig_key_t *memkey,  */
  /* groupsig_key_t *grpkey, unsigned int seed); */
  napi_property_descriptor desc_gs_sign =
    DECLARE_NAPI_METHOD("gs_sign", gs_sign);
  status = napi_define_properties(env, exports, 1, &desc_gs_sign);
  assert(status == napi_ok);

  /* int groupsig_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg,  */
  /* groupsig_key_t *grpkey); */
  napi_property_descriptor desc_gs_verify =
    DECLARE_NAPI_METHOD("gs_verify", gs_verify);
  status = napi_define_properties(env, exports, 1, &desc_gs_verify);
  assert(status == napi_ok);

  /* int groupsig_reveal(trapdoor_t *trap, crl_t *crl, gml_t *gml, uint64_t index); */

  /* int groupsig_open(uint64_t *index, groupsig_proof_t *proof, crl_t *crl,  */
  /* groupsig_signature_t *sig, groupsig_key_t *grpkey,  */
  /* groupsig_key_t *mgrkey, gml_t *gml); */
  napi_property_descriptor desc_gs_open =
    DECLARE_NAPI_METHOD("gs_open", gs_open);
  status = napi_define_properties(env, exports, 1, &desc_gs_open);
  assert(status == napi_ok);  
  
  /* int groupsig_open_verify(uint8_t *ok, */
  /* groupsig_proof_t *proof,  */
  /* groupsig_signature_t *sig,  */
  /* groupsig_key_t *grpkey); */
  napi_property_descriptor desc_gs_open_verify =
    DECLARE_NAPI_METHOD("gs_open_verify", gs_open_verify);
  status = napi_define_properties(env, exports, 1, &desc_gs_open_verify);
  assert(status == napi_ok);    

  /* int groupsig_trace(uint8_t *ok, groupsig_signature_t *sig, groupsig_key_t *grpkey, */
  /* crl_t *crl, groupsig_key_t *mgrkey, gml_t *gml); */

  /* int groupsig_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, groupsig_key_t *grpkey,  */
  /* groupsig_signature_t *sig); */

  /* int groupsig_claim_verify(uint8_t *ok, groupsig_proof_t *proof, groupsig_signature_t *sig,  */
  /* groupsig_key_t *grpkey); */

  /* int groupsig_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey,  */
  /* groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs); */

  /* int groupsig_prove_equality_verify(uint8_t *ok, groupsig_proof_t *proof,  */
  /* groupsig_key_t *grpkey, groupsig_signature_t **sigs,  */
  /* uint16_t n_sigs); */

  /* int groupsig_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey, */
  /* groupsig_key_t *grpkey, groupsig_signature_t *sig, */
  /* message_t *msg); */
  napi_property_descriptor desc_gs_blind =
    DECLARE_NAPI_METHOD("gs_blind", gs_blind);
  status = napi_define_properties(env, exports, 1, &desc_gs_blind);
  assert(status == napi_ok);
   
  /* int groupsig_convert(groupsig_blindsig_t **csig, */
  /* groupsig_blindsig_t **bsig, uint32_t n_bsigs, */
  /* groupsig_key_t *grpkey, groupsig_key_t *mgrkey, */
  /* groupsig_key_t *bldkey, message_t *msg); */
  napi_property_descriptor desc_gs_convert =
    DECLARE_NAPI_METHOD("gs_convert", gs_convert);
  status = napi_define_properties(env, exports, 1, &desc_gs_convert);
  assert(status == napi_ok);

  /* int groupsig_unblind(identity_t *nym, groupsig_signature_t *sig, */
  /* groupsig_blindsig_t *bsig, */
  /* groupsig_key_t *grpkey, groupsig_key_t *bldkey, */
  /* message_t *msg); */
  napi_property_descriptor desc_gs_unblind =
    DECLARE_NAPI_METHOD("gs_unblind", gs_unblind);
  status = napi_define_properties(env, exports, 1, &desc_gs_unblind);
  assert(status == napi_ok);   

  /* int groupsig_get_code_from_str(uint8_t *code, char *name); */
  napi_property_descriptor desc_gs_get_code_from_str =
    DECLARE_NAPI_METHOD("gs_get_code_from_str", gs_get_code_from_str);
  status = napi_define_properties(env, exports, 1, &desc_gs_get_code_from_str);
  assert(status == napi_ok);

  /****** grp_key.h functions ******/

  /* const grp_key_handle_t* groupsig_grp_key_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_grp_key_handle_from_code =
    DECLARE_NAPI_METHOD("gs_grp_key_handle_from_code", gs_grp_key_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_handle_from_code);
  assert(status == napi_ok);  

  /* groupsig_key_t* groupsig_grp_key_init(uint8_t code); */
  napi_property_descriptor desc_gs_grp_key_init =
    DECLARE_NAPI_METHOD("gs_grp_key_init", gs_grp_key_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_init);
  assert(status == napi_ok);  
  
  /* int groupsig_grp_key_free(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_grp_key_free =
    DECLARE_NAPI_METHOD("gs_grp_key_free", gs_grp_key_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_free);
  assert(status == napi_ok);  

  /* int groupsig_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src); */
  napi_property_descriptor desc_gs_grp_key_copy =
    DECLARE_NAPI_METHOD("gs_grp_key_copy", gs_grp_key_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_copy);
  assert(status == napi_ok);  

  /* int groupsig_grp_key_get_size(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_grp_key_get_size =
    DECLARE_NAPI_METHOD("gs_grp_key_get_size", gs_grp_key_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_get_size);
  assert(status == napi_ok);  

  /* int groupsig_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_grp_key_export =
    DECLARE_NAPI_METHOD("gs_grp_key_export", gs_grp_key_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_export);
  assert(status == napi_ok);    
  
  /* groupsig_key_t* groupsig_grp_key_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_grp_key_import =
    DECLARE_NAPI_METHOD("gs_grp_key_import", gs_grp_key_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_import);
  assert(status == napi_ok);  
  
  /* char* groupsig_grp_key_to_string(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_grp_key_to_string =
    DECLARE_NAPI_METHOD("gs_grp_key_to_string", gs_grp_key_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_grp_key_to_string);
  assert(status == napi_ok);  

  /****** mgr_key.h functions ******/

  /* const mgr_key_handle_t* groupsig_mgr_key_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_mgr_key_handle_from_code =
    DECLARE_NAPI_METHOD("gs_mgr_key_handle_from_code", gs_mgr_key_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_handle_from_code);
  assert(status == napi_ok);  

  /* groupsig_key_t* groupsig_mgr_key_init(uint8_t code); */
  napi_property_descriptor desc_gs_mgr_key_init =
    DECLARE_NAPI_METHOD("gs_mgr_key_init", gs_mgr_key_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_init);
  assert(status == napi_ok);  
  
  /* int groupsig_mgr_key_free(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mgr_key_free =
    DECLARE_NAPI_METHOD("gs_mgr_key_free", gs_mgr_key_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_free);
  assert(status == napi_ok);  

  /* int groupsig_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src); */
  napi_property_descriptor desc_gs_mgr_key_copy =
    DECLARE_NAPI_METHOD("gs_mgr_key_copy", gs_mgr_key_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_copy);
  assert(status == napi_ok);  

  /* int groupsig_mgr_key_get_size(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mgr_key_get_size =
    DECLARE_NAPI_METHOD("gs_mgr_key_get_size", gs_mgr_key_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_get_size);
  assert(status == napi_ok);  

  /* int groupsig_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mgr_key_export =
    DECLARE_NAPI_METHOD("gs_mgr_key_export", gs_mgr_key_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_export);
  assert(status == napi_ok);    
  
  /* groupsig_key_t* groupsig_mgr_key_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_mgr_key_import =
    DECLARE_NAPI_METHOD("gs_mgr_key_import", gs_mgr_key_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_import);
  assert(status == napi_ok);  
  
  /* char* groupsig_mgr_key_to_string(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mgr_key_to_string =
    DECLARE_NAPI_METHOD("gs_mgr_key_to_string", gs_mgr_key_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_mgr_key_to_string);
  assert(status == napi_ok);  

  /****** mem_key.h functions ******/

  /* const mem_key_handle_t* groupsig_mem_key_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_mem_key_handle_from_code =
    DECLARE_NAPI_METHOD("gs_mem_key_handle_from_code", gs_mem_key_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_handle_from_code);
  assert(status == napi_ok);  

  /* groupsig_key_t* groupsig_mem_key_init(uint8_t code); */
  napi_property_descriptor desc_gs_mem_key_init =
    DECLARE_NAPI_METHOD("gs_mem_key_init", gs_mem_key_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_init);
  assert(status == napi_ok);  
  
  /* int groupsig_mem_key_free(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mem_key_free =
    DECLARE_NAPI_METHOD("gs_mem_key_free", gs_mem_key_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_free);
  assert(status == napi_ok);  

  /* int groupsig_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src); */
  napi_property_descriptor desc_gs_mem_key_copy =
    DECLARE_NAPI_METHOD("gs_mem_key_copy", gs_mem_key_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_copy);
  assert(status == napi_ok);  

  /* int groupsig_mem_key_get_size(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mem_key_get_size =
    DECLARE_NAPI_METHOD("gs_mem_key_get_size", gs_mem_key_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_get_size);
  assert(status == napi_ok);  

  /* int groupsig_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mem_key_export =
    DECLARE_NAPI_METHOD("gs_mem_key_export", gs_mem_key_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_export);
  assert(status == napi_ok);      

  /* groupsig_key_t* groupsig_mem_key_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_mem_key_import =
    DECLARE_NAPI_METHOD("gs_mem_key_import", gs_mem_key_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_import);
  assert(status == napi_ok);  
  
  /* char* groupsig_mem_key_to_string(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_mem_key_to_string =
    DECLARE_NAPI_METHOD("gs_mem_key_to_string", gs_mem_key_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_mem_key_to_string);
  assert(status == napi_ok);

  /****** bld_key.h functions *****/

  /* const bld_key_handle_t* groupsig_bld_key_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_bld_key_handle_from_code =
    DECLARE_NAPI_METHOD("gs_bld_key_handle_from_code", gs_bld_key_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_handle_from_code);
  assert(status == napi_ok);    

  /* groupsig_key_t* groupsig_bld_key_init(uint8_t code); */
  napi_property_descriptor desc_gs_bld_key_init =
    DECLARE_NAPI_METHOD("gs_bld_key_init", gs_bld_key_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_init);
  assert(status == napi_ok);    

  /* int groupsig_bld_key_free(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_bld_key_free =
    DECLARE_NAPI_METHOD("gs_bld_key_free", gs_bld_key_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_free);
  assert(status == napi_ok);    

  /* int groupsig_bld_key_random(groupsig_key_t *key, void *param); */
  napi_property_descriptor desc_gs_bld_key_random =
    DECLARE_NAPI_METHOD("gs_bld_key_random", gs_bld_key_random);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_random);
  assert(status == napi_ok);      

  /* int groupsig_bld_key_copy(groupsig_key_t *dst, groupsig_key_t *src); */
  napi_property_descriptor desc_gs_bld_key_copy =
    DECLARE_NAPI_METHOD("gs_bld_key_copy", gs_bld_key_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_copy);
  assert(status == napi_ok);  
  
  /* int groupsig_bld_key_get_size(groupsig_key_t *key); */
  napi_property_descriptor desc_gs_bld_key_get_size =
    DECLARE_NAPI_METHOD("gs_bld_key_get_size", gs_bld_key_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_get_size);
  assert(status == napi_ok);  
  
  /* int groupsig_bld_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_bld_key_export =
    DECLARE_NAPI_METHOD("gs_bld_key_export", gs_bld_key_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_export);
  assert(status == napi_ok);

  napi_property_descriptor desc_gs_bld_key_export_pub =
    DECLARE_NAPI_METHOD("gs_bld_key_export_pub", gs_bld_key_export_pub);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_export_pub);
  assert(status == napi_ok); 
  
  /* groupsig_key_t* groupsig_bld_key_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_bld_key_import =
    DECLARE_NAPI_METHOD("gs_bld_key_import", gs_bld_key_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_import);
  assert(status == napi_ok);  
  
  /* char* groupsig_bld_key_to_string(groupsig_key_t *key);   */
  napi_property_descriptor desc_gs_bld_key_to_string =
    DECLARE_NAPI_METHOD("gs_bld_key_to_string", gs_bld_key_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_bld_key_to_string);
  assert(status == napi_ok);

  /****** signature.h functions ******/

  /* const groupsig_signature_handle_t* groupsig_signature_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_signature_handle_from_code =
    DECLARE_NAPI_METHOD("gs_signature_handle_from_code", gs_signature_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_handle_from_code);
  assert(status == napi_ok);

  /* groupsig_signature_t* groupsig_signature_init(uint8_t code); */
  napi_property_descriptor desc_gs_signature_init =
    DECLARE_NAPI_METHOD("gs_signature_init", gs_signature_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_init);
  assert(status == napi_ok);

  /* int groupsig_signature_free(groupsig_signature_t *sig); */
  napi_property_descriptor desc_gs_signature_free =
    DECLARE_NAPI_METHOD("gs_signature_free", gs_signature_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_free);
  assert(status == napi_ok);

  /* Helper function to retrieve the scheme code from a signature */
  napi_property_descriptor desc_gs_signature_get_code =
    DECLARE_NAPI_METHOD("gs_signature_get_code", gs_signature_get_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_get_code);
  assert(status == napi_ok);
  
  /* int groupsig_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src); */
  napi_property_descriptor desc_gs_signature_copy =
    DECLARE_NAPI_METHOD("gs_signature_copy", gs_signature_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_copy);
  assert(status == napi_ok);   

  /* int groupsig_signature_get_size(groupsig_signature_t *sig); */
  napi_property_descriptor desc_gs_signature_get_size =
    DECLARE_NAPI_METHOD("gs_signature_get_size", gs_signature_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_get_size);
  assert(status == napi_ok);     

  /* int groupsig_signature_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_signature_export =
    DECLARE_NAPI_METHOD("gs_signature_export", gs_signature_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_export);
  assert(status == napi_ok);  

  /* groupsig_signature_t* groupsig_signature_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_signature_import =
    DECLARE_NAPI_METHOD("gs_signature_import", gs_signature_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_import);
  assert(status == napi_ok);

  /* char* groupsig_signature_to_string(groupsig_signature_t *sig);   */
  napi_property_descriptor desc_gs_signature_to_string =
    DECLARE_NAPI_METHOD("gs_signature_to_string", gs_signature_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_signature_to_string);
  assert(status == napi_ok);  

  /****** blindsig.h functions ******/

  /* const groupsig_blindsig_handle_t* groupsig_blindsig_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_blindsig_handle_from_code =
    DECLARE_NAPI_METHOD("gs_blindsig_handle_from_code", gs_blindsig_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_handle_from_code);
  assert(status == napi_ok);

  /* groupsig_blindsig_t* groupsig_blindsig_init(uint8_t code); */
  napi_property_descriptor desc_gs_blindsig_init =
    DECLARE_NAPI_METHOD("gs_blindsig_init", gs_blindsig_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_init);
  assert(status == napi_ok);

  /* int groupsig_blindsig_free(groupsig_gs_blindsig_t *sig); */
  napi_property_descriptor desc_gs_blindsig_free =
    DECLARE_NAPI_METHOD("gs_blindsig_free", gs_blindsig_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_free);
  assert(status == napi_ok);  
  
  /* int groupsig_blindsig_copy(groupsig_gs_blindsig_t *dst, groupsig_gs_blindsig_t *src); */
  napi_property_descriptor desc_gs_blindsig_copy =
    DECLARE_NAPI_METHOD("gs_blindsig_copy", gs_blindsig_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_copy);
  assert(status == napi_ok);   

  /* int groupsig_blindsig_get_size(groupsig_blindsig_t *sig); */
  napi_property_descriptor desc_gs_blindsig_get_size =
    DECLARE_NAPI_METHOD("gs_blindsig_get_size", gs_blindsig_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_get_size);
  assert(status == napi_ok);     

  /* int groupsig_blindsig_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_blindsig_export =
    DECLARE_NAPI_METHOD("gs_blindsig_export", gs_blindsig_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_export);
  assert(status == napi_ok);  

  /* groupsig_blindsig_t* groupsig_blindsig_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_blindsig_import =
    DECLARE_NAPI_METHOD("gs_blindsig_import", gs_blindsig_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_import);
  assert(status == napi_ok);

  /* char* groupsig_blindsig_to_string(groupsig_blindsig_t *sig);   */
  napi_property_descriptor desc_gs_blindsig_to_string =
    DECLARE_NAPI_METHOD("gs_blindsig_to_string", gs_blindsig_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_blindsig_to_string);
  assert(status == napi_ok);

  /****** proof.h functions ******/

  /* const groupsig_proof_handle_t* groupsig_proof_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_proof_handle_from_code =
    DECLARE_NAPI_METHOD("gs_proof_handle_from_code", gs_proof_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_handle_from_code);
  assert(status == napi_ok);

  /* groupsig_proof_t* groupsig_proof_init(uint8_t code); */
  napi_property_descriptor desc_gs_proof_init =
    DECLARE_NAPI_METHOD("gs_proof_init", gs_proof_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_init);
  assert(status == napi_ok);

  /* int groupsig_proof_free(groupsig_proof_t *sig); */
  napi_property_descriptor desc_gs_proof_free =
    DECLARE_NAPI_METHOD("gs_proof_free", gs_proof_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_free);
  assert(status == napi_ok);
  
  /* /\* int groupsig_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src); *\/ */
  /* napi_property_descriptor desc_gs_proof_copy = */
  /*   DECLARE_NAPI_METHOD("gs_proof_copy", gs_proof_copy); */
  /* status = napi_define_properties(env, exports, 1, &desc_gs_proof_copy); */
  /* assert(status == napi_ok);    */

  /* int groupsig_proof_get_size(groupsig_proof_t *sig); */
  napi_property_descriptor desc_gs_proof_get_size =
    DECLARE_NAPI_METHOD("gs_proof_get_size", gs_proof_get_size);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_get_size);
  assert(status == napi_ok);     

  /* int groupsig_proof_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key); */
  napi_property_descriptor desc_gs_proof_export =
    DECLARE_NAPI_METHOD("gs_proof_export", gs_proof_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_export);
  assert(status == napi_ok);  

  /* groupsig_proof_t* groupsig_proof_import(uint8_t code, byte_t *bytes, uint32_t size); */
  napi_property_descriptor desc_gs_proof_import =
    DECLARE_NAPI_METHOD("gs_proof_import", gs_proof_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_import);
  assert(status == napi_ok);

  /* char* groupsig_proof_to_string(groupsig_proof_t *sig);   */
  napi_property_descriptor desc_gs_proof_to_string =
    DECLARE_NAPI_METHOD("gs_proof_to_string", gs_proof_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_proof_to_string);
  assert(status == napi_ok);

  /****** identity.h functions ******/

  /* const identity_handle_t* identity_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_identity_handle_from_code =
    DECLARE_NAPI_METHOD("gs_identity_handle_from_code", gs_identity_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_handle_from_code);
  assert(status == napi_ok);

  /* identity_t* identity_init(uint8_t code); */
  napi_property_descriptor desc_gs_identity_init =
    DECLARE_NAPI_METHOD("gs_identity_init", gs_identity_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_init);
  assert(status == napi_ok);

  /* int identity_free(identity_t *id); */
  napi_property_descriptor desc_gs_identity_free =
    DECLARE_NAPI_METHOD("gs_identity_free", gs_identity_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_free);
  assert(status == napi_ok);  
  
  /* int identity_copy(identity_t *dst, identity_t *src); */
  napi_property_descriptor desc_gs_identity_copy =
    DECLARE_NAPI_METHOD("gs_identity_copy", gs_identity_copy);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_copy);
  assert(status == napi_ok);

  /* uint8_t identity_cmp(identity_t *id1, identity_t *id2); */
  napi_property_descriptor desc_gs_identity_cmp =
    DECLARE_NAPI_METHOD("gs_identity_cmp", gs_identity_cmp);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_cmp);
  assert(status == napi_ok);  

  /* char* identity_to_string(identity_t *id); */
  napi_property_descriptor desc_gs_identity_to_string =
    DECLARE_NAPI_METHOD("gs_identity_to_string", gs_identity_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_to_string);
  assert(status == napi_ok);     

  /* identity_t *identity_from_string(uint8_t code, char *sid); */
  napi_property_descriptor desc_gs_identity_from_string =
    DECLARE_NAPI_METHOD("gs_identity_from_string", gs_identity_from_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_identity_from_string);
  assert(status == napi_ok);     

  /****** gml.h functions ******/

  /* const gml_handle_t* gml_handle_from_code(uint8_t code); */
  napi_property_descriptor desc_gs_gml_handle_from_code =
    DECLARE_NAPI_METHOD("gs_gml_handle_from_code", gs_gml_handle_from_code);
  status = napi_define_properties(env, exports, 1, &desc_gs_gml_handle_from_code);
  assert(status == napi_ok);  

  /* gml_t* gml_init(uint8_t scheme); */
  napi_property_descriptor desc_gs_gml_init =
    DECLARE_NAPI_METHOD("gs_gml_init", gs_gml_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_gml_init);
  assert(status == napi_ok);  

  /* int gml_free(gml_t *gml); */
  napi_property_descriptor desc_gs_gml_free =
    DECLARE_NAPI_METHOD("gs_gml_free", gs_gml_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_gml_free);
  assert(status == napi_ok);    

  /* int gml_insert(gml_t *gml, void *entry); */

  /* int gml_remove(gml_t *gml, uint64_t index); */

  /* void* gml_get(gml_t *gml, uint64_t index); */

  /* int gml_export(gml_t *gml, void *dst, gml_format_t format); */
  napi_property_descriptor desc_gs_gml_export =
    DECLARE_NAPI_METHOD("gs_gml_export", gs_gml_export);
  status = napi_define_properties(env, exports, 1, &desc_gs_gml_export);
  assert(status == napi_ok);  

  /* gml_t* gml_import(uint8_t code, gml_format_t format, void *source); */  
  napi_property_descriptor desc_gs_gml_import =
    DECLARE_NAPI_METHOD("gs_gml_import", gs_gml_import);
  status = napi_define_properties(env, exports, 1, &desc_gs_gml_import);
  assert(status == napi_ok);
  
  /* int gml_export_new_entry(uint8_t scheme, void *entry, void *dst,  */
  /* 			   gml_format_t format); */


  /* int gml_compare_entries(int *eq, void *entry1, void *entry2, gml_cmp_entries_f cmp);   */

 /* message_t* message_init(); */
  napi_property_descriptor desc_gs_message_init =
    DECLARE_NAPI_METHOD("gs_message_init", gs_message_init);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_init);
  assert(status == napi_ok);  

  /* int message_free(message_t *message); */
  napi_property_descriptor desc_gs_message_free =
    DECLARE_NAPI_METHOD("gs_message_free", gs_message_free);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_free);
  assert(status == napi_ok);

  /* message_t* message_from_string(char *str); */
  napi_property_descriptor desc_gs_message_from_string =
    DECLARE_NAPI_METHOD("gs_message_from_string", gs_message_from_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_from_string);
  assert(status == napi_ok);

  /* char* message_to_string(message_t *id); */
  napi_property_descriptor desc_gs_message_to_string =
    DECLARE_NAPI_METHOD("gs_message_to_string", gs_message_to_string);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_to_string);
  assert(status == napi_ok);

  /* message_t* message_from_stringb64(char *str); */
  napi_property_descriptor desc_gs_message_from_stringb64 =
    DECLARE_NAPI_METHOD("gs_message_from_stringb64", gs_message_from_stringb64);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_from_stringb64);
  assert(status == napi_ok);

  /* char* message_to_stringb64(message_t *id); */
  napi_property_descriptor desc_gs_message_to_stringb64 =
    DECLARE_NAPI_METHOD("gs_message_to_stringb64", gs_message_to_stringb64);
  status = napi_define_properties(env, exports, 1, &desc_gs_message_to_stringb64);
  assert(status == napi_ok);    
  

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
