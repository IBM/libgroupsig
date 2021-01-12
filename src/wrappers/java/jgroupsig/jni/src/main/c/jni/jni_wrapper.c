#include <stdio.h>
#include <stdlib.h>
#include <jni.h>

#include "groupsig.h"
#include "grp_key.h"
#include "mgr_key.h"
#include "mem_key.h"
#include "bld_key.h"
#include "identity.h"
#include "message.h"
#include "signature.h"
#include "blindsig.h"
#include <limits.h>

static const char *JNIT_CLASS_GL19 = "com/ibm/jgroupsig/GL19";
static const char *JNIT_CLASS_BBS04 = "com/ibm/jgroupsig/BBS04";
static const char *JNIT_CLASS_PS16 = "com/ibm/jgroupsig/PS16";
static const char *JNIT_CLASS_GRPKEY = "com/ibm/jgroupsig/GrpKey";
static const char *JNIT_CLASS_MGRKEY = "com/ibm/jgroupsig/MgrKey";
static const char *JNIT_CLASS_MEMKEY = "com/ibm/jgroupsig/MemKey";
static const char *JNIT_CLASS_BLDKEY = "com/ibm/jgroupsig/BldKey";
static const char *JNIT_CLASS_IDENTITY = "com/ibm/jgroupsig/Identity";
static const char *JNIT_CLASS_GML = "com/ibm/jgroupsig/Gml";
static const char *JNIT_CLASS_SIGNATURE = "com/ibm/jgroupsig/Signature";
static const char *JNIT_CLASS_BLINDSIG = "com/ibm/jgroupsig/BlindSignature";
static const char *JNIT_CLASS_PROOF = "com/ibm/jgroupsig/Proof";


/********** GS functions **********/
/* static void gs_destroy(JNIEnv *env, jobject obj) { */
  
/*   (void) env; */
/*   (void) obj; */

/*   return (jint) groupsig_hello_world(); */

/* } */

static jint groupsig_gsHelloWorld(JNIEnv *env,
				  jobject obj) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_hello_world();

}

static jboolean groupsig_gsIsSupportedScheme(JNIEnv *env,
					     jobject obj,
					     jint code) {

  int b;
  jclass jcls;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return JNI_FALSE;
  }
  
  b = (jint) groupsig_is_supported_scheme((uint8_t) code);

  if (b) return JNI_TRUE;
  return JNI_FALSE;

}

static jint groupsig_gsGetCodeFromStr(JNIEnv *env,
				      jobject obj,
				      jstring str) {

  const char *_str;
  groupsig_t *gs;
  jclass jcls; 
  
  (void) env;
  (void) obj;
  
  if (!str) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) -1;
  }

  _str  = (*env)->GetStringUTFChars(env, str, 0);
  if(!(gs = (groupsig_t *) groupsig_get_groupsig_from_str((char *) _str))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) -1;
  }
  (*env)->ReleaseStringUTFChars(env, str, _str);

  return (jint) gs->desc->code;
  
}

static jlong groupsig_gsGetFromStr(JNIEnv *env,
				   jobject obj,
				   jstring str) {

  const char *_str;
  groupsig_t *gs;
  jclass jcls;   
  
  (void) env;
  (void) obj;
  
  if (!str) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;    
  }  

  _str  = (*env)->GetStringUTFChars(env, str, 0);
  gs = (groupsig_t *) groupsig_get_groupsig_from_str((char *) _str);
  (*env)->ReleaseStringUTFChars(env, str, _str);

  return (jlong) gs;
  
}

static jlong groupsig_gsGetFromCode(JNIEnv *env,
				    jobject obj,
				    jint code) {
  
  groupsig_t *gs;
  jclass jcls;  
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;    
  }    
  
  if(!(gs = (groupsig_t *) groupsig_get_groupsig_from_code((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) gs;
  
}

static jint groupsig_gsInit(JNIEnv *env,
			     jobject obj,
			     jint code,
			     jint seed) {

  jclass jcls;
  int rc;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX || (int) seed > UINT_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }      

  if(groupsig_init(code, seed) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  return (jint) IOK;

}

static jint groupsig_gsClear(JNIEnv *env,
			     jobject obj,
			     jint code) {

  jclass jcls;
  int rc;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }      

  rc = groupsig_clear((uint8_t) code);
  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
  }

  return (jint) rc;

}

static jboolean groupsig_gsHasGml(JNIEnv *env,
				  jobject obj,
				  jint code) {

  jclass jcls;
  groupsig_t *gs;
  uint8_t b;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) JNI_FALSE;    
  }

  if(!(gs = (groupsig_t *) groupsig_get_groupsig_from_code((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) JNI_FALSE;
  }  

  b = gs->desc->has_gml;
  if (b) return JNI_TRUE;
  return JNI_FALSE;

}

static jint groupsig_gsSetup(JNIEnv *env,
			     jobject obj,
			     jint code,
			     jlong grpKeyPtr,
			     jlong mgrKeyPtr,
			     jlong gmlPtr) {

  jclass jcls;
  int rc;

  (void) env;
  (void) obj;

  if (!grpKeyPtr || !mgrKeyPtr || (int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }    

  rc= groupsig_setup((uint8_t) code,
		     (groupsig_key_t *) grpKeyPtr,
		     (groupsig_key_t *) mgrKeyPtr, 
		     (gml_t *) gmlPtr);

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
  }

  return (jint) rc;

}

static jint groupsig_gsGetJoinSeq(JNIEnv *env,
				  jobject obj,
				  jint code) {

  jclass jcls;
  int rc;
  uint8_t seq;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) -1;    
  }      

  if((rc = groupsig_get_joinseq((uint8_t) code, &seq)) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) -1;
  }
  
  return (jint) seq;
  
}
				  
static jint groupsig_gsGetJoinStart(JNIEnv *env,
				    jobject obj,
				    jint code) {

  jclass jcls;
  int rc;
  uint8_t start;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) -1;    
  }      

  if((rc = groupsig_get_joinstart((uint8_t) code, &start)) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return -1;
  }
  
  return (jint) start;
  
}				  

static jlong groupsig_gsJoinMem(JNIEnv *env,
				jobject obj,
				jlong memKeyPtr,
				jint seq,
				jlong minPtr,
				jlong grpKeyPtr) {
  
  jclass jcls;
  message_t *mout;
  int rc;
  uint8_t start;
  
  (void) env;
  (void) obj;

  if (!memKeyPtr || !minPtr || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;    
  }        

  mout = NULL;
  rc = groupsig_join_mem((message_t **) &mout,
			 (groupsig_key_t *) memKeyPtr,
			 seq,
			 (message_t *) minPtr,
			 (groupsig_key_t *) grpKeyPtr);

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) mout;
  
}

static jlong groupsig_gsJoinMgr(JNIEnv *env,
				jobject obj,
				jlong gmlPtr,
				jlong mgrKeyPtr,
				jint seq,
				jlong minPtr,
				jlong grpKeyPtr) {

  jclass jcls;
  message_t *mout;
  int rc;
  uint8_t start;
  
  (void) env;
  (void) obj;

  if (!mgrKeyPtr || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;    
  }

  mout = NULL;
  rc = groupsig_join_mgr((message_t **) &mout,
			 (gml_t *) gmlPtr,
			 (groupsig_key_t *) mgrKeyPtr,
			 seq,
			 (message_t *) minPtr,
			 (groupsig_key_t *) grpKeyPtr);

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) mout;
  
}

static jint groupsig_gsSign(JNIEnv *env,
			    jobject obj,
			    jlong sigPtr,
			    jbyteArray msg,
			    jint msgLen,
			    jlong memKeyPtr,
			    jlong grpKeyPtr,
			    jint seed) {

  jclass jcls;
  message_t *_msg;
  int rc;
  /* int size; */
  byte_t *bytes;
  
  (void) env;
  (void) obj;

  if (!sigPtr || msgLen <= 0 || !memKeyPtr || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }

  if(!(bytes = (byte_t *) malloc(sizeof(byte_t)*msgLen))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, msg, 0, msgLen, (jbyte *) bytes);
  if(!(_msg = message_from_bytes(bytes, (uint64_t) msgLen))) {
    free(bytes); bytes = NULL;
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");    
    return IERROR;
  }

  rc = groupsig_sign((groupsig_signature_t *) sigPtr,
		     _msg, 
		     (groupsig_key_t *) memKeyPtr, 
		     (groupsig_key_t *) grpKeyPtr,
		     (unsigned int) seed);

  message_free(_msg); _msg = NULL;
  free(bytes); bytes = NULL;
  
  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }
  
  return (jint) rc;
  
}

static jboolean groupsig_gsVerify(JNIEnv *env,
				  jobject obj,
				  jlong sigPtr,
				  jbyteArray msg,
				  jint msgLen,
				  jlong grpKeyPtr) {

  jclass jcls;
  byte_t *bytes;
  message_t *_msg;
  int rc;
  uint8_t b;
  
  (void) env;
  (void) obj;

  if (!sigPtr || msgLen <= 0 || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return JNI_FALSE;    
  }

  if(!(bytes = (byte_t *) malloc(sizeof(byte_t)*msgLen))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");    
    return JNI_FALSE;
  }

  (*env)->GetByteArrayRegion(env, msg, 0, msgLen, (jbyte *)  bytes);
  if(!(_msg = message_from_bytes(bytes, (uint64_t) msgLen))) {
    free(bytes); bytes = NULL;
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return JNI_FALSE;
  }
  
  rc = groupsig_verify(&b,
		       (groupsig_signature_t *) sigPtr,
		       _msg,
		       (groupsig_key_t *) grpKeyPtr);
  
  message_free(_msg); _msg = NULL;
  free(bytes); bytes = NULL;
  
  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return JNI_FALSE;
  }

  if (b) return JNI_TRUE;
  return JNI_FALSE;
  
}

static jlong groupsig_gsOpen(JNIEnv *env,
			    jobject obj,
			    jlong proofPtr,
			    jlong crlPtr,
			    jlong sigPtr,
			    jlong grpKeyPtr,
			    jlong mgrKeyPtr,
			    jlong gmlPtr) {
  
  jclass jcls;
  uint64_t index;
  int rc;
  
  (void) env;
  (void) obj;

  if (!sigPtr || !grpKeyPtr || !mgrKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }

  rc = groupsig_open(&index,
		     (groupsig_proof_t *) proofPtr,
		     (crl_t *) crlPtr,
		     (groupsig_signature_t *) sigPtr,
		     (groupsig_key_t *) grpKeyPtr,
		     (groupsig_key_t *) mgrKeyPtr,
		     (gml_t *) gmlPtr);

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) UINT_MAX;
  }

  /* Note: jlong is interpreted by java as a signed integer of 64 bits,
     while index is an unsigned int of 64 bits. But there are no larger
     int data types in JNI, so this must be dealt with outside of it. */
  return (jlong) index;
  
}

static jboolean groupsig_gsOpenVerify(JNIEnv *env,
				      jobject obj,
				      jlong proofPtr,
				      jlong sigPtr,
				      jlong grpKeyPtr) {

  jclass jcls;
  int rc;
  uint8_t ok;
  
  (void) env;
  (void) obj;

  if (!proofPtr || !sigPtr || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return JNI_FALSE;    
  }

  rc = groupsig_open_verify(&ok,
			    (groupsig_proof_t *) proofPtr,
			    (groupsig_signature_t *) sigPtr,
			    (groupsig_key_t *) grpKeyPtr);

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return JNI_FALSE;
  }

  if (ok) return JNI_TRUE;
  return JNI_FALSE;  
    
}

static jint groupsig_gsBlind(JNIEnv *env,
			     jobject obj,
			     jlong bSigPtr,
			     jlong bldKeyPtr,
			     jlong grpKeyPtr,
			     jlong sigPtr,
			     jbyteArray msg,
			     jint msgLen) {

  jclass jcls;
  message_t *_msg;
  byte_t *bytes;
  int rc;
  
  (void) env;
  (void) obj;

  if (!bSigPtr ||  !bldKeyPtr || !grpKeyPtr || !sigPtr || msgLen <= 0) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;    
  }

  if(!(bytes = (byte_t *) malloc(sizeof(byte_t)*msgLen))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");    
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, msg, 0, msgLen, (jbyte *)  bytes);
  if(!(_msg = message_from_bytes(bytes, (uint64_t) msgLen))) {
    free(bytes); bytes = NULL;
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }
  
  rc = groupsig_blind((groupsig_blindsig_t *) bSigPtr,
		      (groupsig_key_t **) &bldKeyPtr,
		      (groupsig_key_t *) grpKeyPtr,
		      (groupsig_signature_t *) sigPtr,
		      _msg);

  message_free(_msg); _msg = NULL;
  free(bytes); bytes = NULL;

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
  }
  
  return (jint) rc;
  
}

static jint groupsig_gsConvert(JNIEnv *env,
			       jobject obj,
			       jlongArray cSigsPtr,
			       jlongArray bSigsPtr,
			       jint bSigsLen,
			       jlong grpKeyPtr,
			       jlong mgrKeyPtr,
			       jlong bldKeyPtr,
			       jbyteArray msg,
			       jint msgLen) {
  
  jclass jcls;
  message_t *_msg;
  byte_t *bytes;
  jlong *cSigs, *bSigs;
  int i, rc;
  uint8_t start;
  
  (void) env;
  (void) obj;

  if (!cSigsPtr || !bSigsPtr || bSigsLen <= 0 || !grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jint) IERROR;
  }

  if(!(cSigs = (jlong *) malloc(sizeof(jlong)*bSigsLen))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error1.");    
    return (jint) IERROR;
  }
  (*env)->GetLongArrayRegion(env, cSigsPtr, 0, (jsize) bSigsLen, cSigs);
 
  if(!(bSigs = (jlong *) malloc(sizeof(jlong)*bSigsLen))) {
    free(cSigs); cSigs = NULL;
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error2.");
    return (jint) IERROR;
  }
  (*env)->GetLongArrayRegion(env, bSigsPtr, 0, (int) bSigsLen, bSigs);  

  if(msg) {
    if(!(bytes = (byte_t *) malloc(sizeof(byte_t)*msgLen))) {
      free(cSigs); cSigs = NULL;
      free(bSigs); bSigs = NULL;
      jcls = (*env)->FindClass(env, "java/lang/Exception");
      (*env)->ThrowNew(env, jcls, "Internal error3.");
      return (jint) IERROR;
    }

    (*env)->GetByteArrayRegion(env, msg, 0, msgLen, (jbyte *)  bytes);
    if(!(_msg = message_from_bytes(bytes, (uint64_t) msgLen))) {
      free(bytes); bytes = NULL;
      free(cSigs); cSigs = NULL;
      free(bSigs); bSigs = NULL;
      jcls = (*env)->FindClass(env, "java/lang/Exception");
      (*env)->ThrowNew(env, jcls, "Internal error4.");      
      return (jint) IERROR;
    }
  } else {
    _msg = NULL;
  }
  
  rc = groupsig_convert((groupsig_blindsig_t **) cSigs,
			(groupsig_blindsig_t **) bSigs,
			(uint32_t) bSigsLen,
			(groupsig_key_t *) grpKeyPtr,
			(groupsig_key_t *) mgrKeyPtr,
			(groupsig_key_t *) bldKeyPtr,
			_msg);

  if(_msg) {
    message_free(_msg); _msg = NULL;
    free(bytes); bytes = NULL;
  }

  if (rc == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error5.");
    return (jint) IERROR;
  }

  /* (*env)->ReleaseLongArrayElements(env, cSigsPtr, cSigs, 0); */
  /* (*env)->ReleaseLongArrayElements(env, bSigsPtr, bSigs, 0); */

  return (jint) IOK;
  
}

static jbyteArray groupsig_gsUnblind(JNIEnv *env,
				     jobject obj,
				     jlong idPtr,
				     jlong sigPtr,
				     jlong bSigPtr,
				     jlong grpKeyPtr,
				     jlong bldKeyPtr) {

  jclass jcls;
  message_t *msg;
  jbyteArray result;
  int rc;
  
  (void) env;
  (void) obj;

  if (!idPtr || !bSigPtr || !bldKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return NULL;    
  }

  if(!(msg = message_init())) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;    
  }
  
  rc = groupsig_unblind((identity_t *) idPtr,
			(groupsig_signature_t *) sigPtr,
			(groupsig_blindsig_t *) bSigPtr,
			(groupsig_key_t *) grpKeyPtr,
			(groupsig_key_t *) bldKeyPtr,
			msg);

  if (rc == IERROR) {
    message_free(msg); msg = NULL;
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }
  
  result=(*env)->NewByteArray(env, msg->length);
  (*env)->SetByteArrayRegion(env, result, 0, msg->length, (const jbyte *) msg->bytes);
  message_free(msg); msg = NULL;
    
  return result;

}

static JNINativeMethod funcs_gs[] = {
  { "groupsig_gsHelloWorld", "()I", (void *) &groupsig_gsHelloWorld },
  { "groupsig_gsIsSupportedScheme", "(I)Z", (void *) &groupsig_gsIsSupportedScheme },
  { "groupsig_gsGetCodeFromStr", "(Ljava/lang/String;)I", (void *) &groupsig_gsGetCodeFromStr },
  { "groupsig_gsGetFromStr", "(Ljava/lang/String;)J", (void *) &groupsig_gsGetFromStr },
  { "groupsig_gsGetFromCode", "(I)J", (void *) &groupsig_gsGetFromCode },
  { "groupsig_gsInit", "(II)I", (void *) &groupsig_gsInit },
  { "groupsig_gsClear", "(I)I", (void *) &groupsig_gsClear },
  { "groupsig_gsHasGml", "(I)Z", (void *) &groupsig_gsHasGml },
  { "groupsig_gsSetup", "(IJJJ)I", (void *) &groupsig_gsSetup },
  { "groupsig_gsGetJoinSeq", "(I)I", (void *) &groupsig_gsGetJoinSeq },
  { "groupsig_gsGetJoinStart", "(I)I", (void *) &groupsig_gsGetJoinStart },
  { "groupsig_gsJoinMem", "(JIJJ)J", (void *) &groupsig_gsJoinMem },
  { "groupsig_gsJoinMgr", "(JJIJJ)J", (void *) &groupsig_gsJoinMgr },
  { "groupsig_gsSign", "(J[BIJJI)I", (void *) &groupsig_gsSign },
  { "groupsig_gsVerify", "(J[BIJ)Z", (void *) &groupsig_gsVerify },
  /* { "groupsig_gsReveal", , }, */
  { "groupsig_gsOpen", "(JJJJJJ)J", (void *) &groupsig_gsOpen },
  { "groupsig_gsOpenVerify", "(JJJ)Z", (void *) &groupsig_gsOpenVerify },
  /* { "groupsig_gsTrace", , }, */
  /* { "groupsig_gsClaim", , }, */
  /* { "groupsig_gsClaimVerify", , }, */
  { "groupsig_gsBlind", "(JJJJ[BI)I", (void *) &groupsig_gsBlind },
  { "groupsig_gsConvert", "([J[JIJJJ[BI)I", (void *) &groupsig_gsConvert },
  { "groupsig_gsUnblind", "(JJJJJ)[B", (void *) &groupsig_gsUnblind },
};
 
/********** GrpKey functions **********/
 
static jlong groupsig_grpKeyInit(JNIEnv *env,
				 jobject obj,
				 jint code) {
  
  jclass jcls;
  groupsig_key_t *key;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  key = groupsig_grp_key_init((uint8_t) code);
  if (!key) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  
  return (jlong) key;
  
}

static jint groupsig_grpKeyFree(JNIEnv *env,
				jobject obj,
				jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_grp_key_free((groupsig_key_t *) ptr);
  
}

static jint groupsig_grpKeyGetCode(JNIEnv *env,
				   jobject obj,
				   jlong ptr) {
  
  jclass jcls;
  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_key_t *) ptr)->scheme;

}
  
static jbyteArray groupsig_grpKeyExport(JNIEnv *env,
					jobject obj,
					long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_grp_key_export(&bytes, &size, (groupsig_key_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_grpKeyImport(JNIEnv *env,
				   jobject obj,
				   int code,
				   jbyteArray bytes,
				   int size) {
  jclass jcls;
  groupsig_key_t *key;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(key = groupsig_grp_key_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) key;
  
}

static JNINativeMethod funcs_grpkey[] = {
  { "groupsig_grpKeyInit", "(I)J", (void *) &groupsig_grpKeyInit },
  { "groupsig_grpKeyFree", "(J)I", (void *) &groupsig_grpKeyFree },
  { "groupsig_grpKeyGetCode", "(J)I", (void *) &groupsig_grpKeyGetCode },
  { "groupsig_grpKeyExport", "(J)[B", (void *) &groupsig_grpKeyExport },
  { "groupsig_grpKeyImport", "(I[BI)J", (void *) &groupsig_grpKeyImport },
};

/********** MgrKey functions **********/

static jlong groupsig_mgrKeyInit(JNIEnv *env,
				 jobject obj,
				 jint code) {
  
  jclass jcls;
  groupsig_key_t *key;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(key = groupsig_mgr_key_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) key;
  
}

static jint groupsig_mgrKeyFree(JNIEnv *env,
				jobject obj,
				jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_mgr_key_free((groupsig_key_t *) ptr);
  
}

static jint groupsig_mgrKeyGetCode(JNIEnv *env,
				   jobject obj,
				   jlong ptr) {
  
  jclass jcls;
  
  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_key_t *) ptr)->scheme;

}
  
static jbyteArray groupsig_mgrKeyExport(JNIEnv *env,
					jobject obj,
					long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_mgr_key_export(&bytes, &size, (groupsig_key_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_mgrKeyImport(JNIEnv *env,
				   jobject obj,
				   int code,
				   jbyteArray bytes,
				   int size) {
  jclass jcls;
  groupsig_key_t *key;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(key = groupsig_mgr_key_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) key;
  
}

static JNINativeMethod funcs_mgrkey[] = {
  { "groupsig_mgrKeyInit", "(I)J", (void *) &groupsig_mgrKeyInit },
  { "groupsig_mgrKeyFree", "(J)I", (void *) &groupsig_mgrKeyFree },
  { "groupsig_mgrKeyGetCode", "(J)I", (void *) &groupsig_mgrKeyGetCode },
  { "groupsig_mgrKeyExport", "(J)[B", (void *) &groupsig_mgrKeyExport },
  { "groupsig_mgrKeyImport", "(I[BI)J", (void *) &groupsig_mgrKeyImport },
};

/********** MemKey functions **********/

static jlong groupsig_memKeyInit(JNIEnv *env,
				 jobject obj,
				 jint code) {

  jclass jcls;
  groupsig_key_t *key;
  
  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(key = groupsig_mem_key_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) key;
  
}

static jint groupsig_memKeyFree(JNIEnv *env,
				jobject obj,
				jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_mem_key_free((groupsig_key_t *) ptr);
  
}

static jint groupsig_memKeyGetCode(JNIEnv *env,
				   jobject obj,
				   jlong ptr) {
  
  jclass jcls;
  
  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_key_t *) ptr)->scheme;

}
  
static jbyteArray groupsig_memKeyExport(JNIEnv *env,
					jobject obj,
					long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_mem_key_export(&bytes, &size, (groupsig_key_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_memKeyImport(JNIEnv *env,
				   jobject obj,
				   int code,
				   jbyteArray bytes,
				   int size) {
  jclass jcls;
  groupsig_key_t *key;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(key = groupsig_mem_key_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) key;
  
}

static JNINativeMethod funcs_memkey[] = {
  { "groupsig_memKeyInit", "(I)J", (void *) &groupsig_memKeyInit },
  { "groupsig_memKeyFree", "(J)I", (void *) &groupsig_memKeyFree },
  { "groupsig_memKeyGetCode", "(J)I", (void *) &groupsig_memKeyGetCode },
  { "groupsig_memKeyExport", "(J)[B", (void *) &groupsig_memKeyExport },
  { "groupsig_memKeyImport", "(I[BI)J", (void *) &groupsig_memKeyImport },
};

/********** BldKey functions **********/

static jlong groupsig_bldKeyInit(JNIEnv *env,
				 jobject obj,
				 jint code) {
  
  jclass jcls;
  groupsig_key_t *key;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(key = groupsig_bld_key_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) key;
  
}

static jint groupsig_bldKeyFree(JNIEnv *env,
				jobject obj,
				jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_bld_key_free((groupsig_key_t *) ptr);
  
}

static jlong groupsig_bldKeyRandom(JNIEnv *env,
				   jobject obj,
				   jint code,
				   jlong grpKeyPtr) {
  
  jclass jcls;
  groupsig_key_t *key;
  int rc;

  (void) env;
  (void) obj;
 
  if (!grpKeyPtr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  } 

  key = groupsig_bld_key_random((uint8_t) code,	(void *) grpKeyPtr);
  if(key == NULL) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
  }

  return (jlong) key;  
  
}

static jint groupsig_bldKeyGetCode(JNIEnv *env,
				   jobject obj,
				   jlong ptr) {
  
  jclass jcls;

  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_key_t *) ptr)->scheme;

}

static jbyteArray groupsig_bldKeyExport(JNIEnv *env,
					jobject obj,
					long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_bld_key_export(&bytes, &size, (groupsig_key_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jbyteArray groupsig_bldKeyExportPub(JNIEnv *env,
					   jobject obj,
					   long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_bld_key_export_pub(&bytes, &size,
				 (groupsig_key_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  return result;
  
}

static jlong groupsig_bldKeyImport(JNIEnv *env,
				   jobject obj,
				   int code,
				   jbyteArray bytes,
				   int size) {
  jclass jcls;
  groupsig_key_t *key;
  byte_t *_bytes;

  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(key = groupsig_bld_key_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  free(_bytes); _bytes = NULL;

  return (jlong) key;
  
}

static JNINativeMethod funcs_bldkey[] = {
  { "groupsig_bldKeyInit", "(I)J", (void *) &groupsig_bldKeyInit },
  { "groupsig_bldKeyFree", "(J)I", (void *) &groupsig_bldKeyFree },
  { "groupsig_bldKeyRandom", "(IJ)J", (void *) &groupsig_bldKeyRandom },
  { "groupsig_bldKeyGetCode", "(J)I", (void *) &groupsig_bldKeyGetCode },
  { "groupsig_bldKeyExport", "(J)[B", (void *) &groupsig_bldKeyExport },
  { "groupsig_bldKeyExportPub", "(J)[B", (void *) &groupsig_bldKeyExportPub },					 
					 
  { "groupsig_bldKeyImport", "(I[BI)J", (void *) &groupsig_bldKeyImport },
};

/********** Identity functions **********/

static jlong groupsig_identityInit(JNIEnv *env,
				   jobject obj,
				   jint code) {
  
  jclass jcls;
  identity_t *id;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }

  if(!(id = identity_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) id;
  
}

static jint groupsig_identityFree(JNIEnv *env,
				  jobject obj,
				  jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) identity_free((identity_t *) ptr);
  
}

static jstring groupsig_identityToString(JNIEnv *env, jobject obj, jlong ptr) {

  jclass jcls;
  char *str;

  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }
   
  if(!(str = identity_to_string((identity_t *) ptr))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }
  
  return (*env)->NewStringUTF(env, str);

}

static JNINativeMethod funcs_identity[] = {
  { "groupsig_identityInit", "(I)J", (void *) &groupsig_identityInit },
  { "groupsig_identityFree", "(J)I", (void *) &groupsig_identityFree },
  { "groupsig_identityToString", "(J)Ljava/lang/String;", (void *) &groupsig_identityToString },
};

/********** Gml functions **********/

static jlong groupsig_gmlInit(JNIEnv *env,
			      jobject obj,
			      jint code) {
  
  jclass jcls;
  gml_t *gml;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(gml = gml_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) gml;
  
}

static jint groupsig_gmlFree(JNIEnv *env,
			     jobject obj,
			     jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) gml_free((gml_t *) ptr);
  
}

static jbyteArray groupsig_gmlExport(JNIEnv *env,
					jobject obj,
					long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(gml_export(&bytes, &size, (gml_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_gmlImport(JNIEnv *env,
				   jobject obj,
				   int code,
				   jbyteArray bytes,
				   int size) {
  jclass jcls;
  gml_t *gml;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(gml = gml_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) gml;
  
}

static JNINativeMethod funcs_gml[] = {
  { "groupsig_gmlInit", "(I)J", (void *) &groupsig_gmlInit },
  { "groupsig_gmlFree", "(J)I", (void *) &groupsig_gmlFree },
  { "groupsig_gmlExport", "(J)[B", (void *) &groupsig_gmlExport },
  { "groupsig_gmlImport", "(I[BI)J", (void *) &groupsig_gmlImport }
};

/********** Signature functions **********/

static jlong groupsig_signatureInit(JNIEnv *env,
				    jobject obj,
				    jint code) {
  
  jclass jcls;
  groupsig_signature_t *sig;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(sig = groupsig_signature_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) sig;
  
}

static jint groupsig_signatureFree(JNIEnv *env,
				   jobject obj,
				   jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_signature_free((groupsig_signature_t *) ptr);
  
}

static jint groupsig_signatureGetCode(JNIEnv *env,
				      jobject obj,
				      jlong ptr) {
  
  jclass jcls;

  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_signature_t *) ptr)->scheme;

}

static jbyteArray groupsig_signatureExport(JNIEnv *env,
					   jobject obj,
					   long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_signature_export(&bytes, &size,
			       (groupsig_signature_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_signatureImport(JNIEnv *env,
				      jobject obj,
				      int code,
				      jbyteArray bytes,
				      int size) {
  jclass jcls;
  groupsig_signature_t *sig;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(sig = groupsig_signature_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) sig;
  
}

static JNINativeMethod funcs_signature[] = {
  { "groupsig_signatureInit", "(I)J", (void *) &groupsig_signatureInit },
  { "groupsig_signatureFree", "(J)I", (void *) &groupsig_signatureFree },
  { "groupsig_signatureGetCode", "(J)I", (void *) &groupsig_signatureGetCode },
  { "groupsig_signatureExport", "(J)[B", (void *) &groupsig_signatureExport },
  { "groupsig_signatureImport", "(I[BI)J", (void *) &groupsig_signatureImport },
};

/********** BlindSignature functions **********/

static jlong groupsig_blindSignatureInit(JNIEnv *env,
					 jobject obj,
					 jint code) {
  
  jclass jcls;
  groupsig_blindsig_t *bsig;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(bsig = groupsig_blindsig_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) bsig;
  
}

static jint groupsig_blindSignatureFree(JNIEnv *env,
					jobject obj,
					jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_blindsig_free((groupsig_blindsig_t *) ptr);
  
}

static jint groupsig_blindSignatureGetCode(JNIEnv *env,
					   jobject obj,
					   jlong ptr) {
  
  jclass jcls;

  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_blindsig_t *) ptr)->scheme;

}

static jbyteArray groupsig_blindSignatureExport(JNIEnv *env,
						jobject obj,
						long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_blindsig_export(&bytes, &size,
			      (groupsig_blindsig_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_blindSignatureImport(JNIEnv *env,
					   jobject obj,
					   int code,
					   jbyteArray bytes,
					   int size) {
  jclass jcls;
  groupsig_blindsig_t *sig;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(sig = groupsig_blindsig_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  
  return (jlong) sig;
  
}

static JNINativeMethod funcs_blindsig[] = {
  { "groupsig_blindSignatureInit", "(I)J", (void *) &groupsig_blindSignatureInit },
  { "groupsig_blindSignatureFree", "(J)I", (void *) &groupsig_blindSignatureFree },
  { "groupsig_blindSignatureGetCode", "(J)I", (void *) &groupsig_blindSignatureGetCode },
  { "groupsig_blindSignatureExport", "(J)[B", (void *) &groupsig_blindSignatureExport },
  { "groupsig_blindSignatureImport", "(I[BI)J", (void *) &groupsig_blindSignatureImport },
};

/********** Proof functions **********/

static jlong groupsig_proofInit(JNIEnv *env,
				jobject obj,
				jint code) {
  
  jclass jcls;
  groupsig_proof_t *proof;

  (void) env;
  (void) obj;

  if ((int) code > UINT8_MAX) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Invalid argument.");
    return (jlong) 0;
  }
  
  if(!(proof = groupsig_proof_init((uint8_t) code))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }

  return (jlong) proof;
  
}

static jint groupsig_proofFree(JNIEnv *env,
			       jobject obj,
			       jlong ptr) {
  
  (void) env;
  (void) obj;

  return (jint) groupsig_proof_free((groupsig_proof_t *) ptr);
  
}

static jint groupsig_proofGetCode(JNIEnv *env,
				  jobject obj,
				  jlong ptr) {
  
  jclass jcls;

  (void) env;
  (void) obj;

  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jint) IERROR;
  }
  
  return ((groupsig_proof_t *) ptr)->scheme;

}

static jbyteArray groupsig_proofExport(JNIEnv *env,
				       jobject obj,
				       long ptr) {

  jclass jcls;
  jbyteArray result;
  byte_t *bytes;
  uint32_t size;
  int len;
  
  if (!ptr) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return NULL;
  }

  bytes = NULL;
  if(groupsig_proof_export(&bytes, &size,
			   (groupsig_proof_t *) ptr) == IERROR) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return NULL;
  }

  result=(*env)->NewByteArray(env, size);
  (*env)->SetByteArrayRegion(env, result, 0, size, (const jbyte *) bytes);
  
  return result;
  
}

static jlong groupsig_proofImport(JNIEnv *env,
				  jobject obj,
				  int code,
				  jbyteArray bytes,
				  int size) {
  jclass jcls;
  groupsig_proof_t *proof;
  byte_t *_bytes;
  
  if (!bytes || !size) {
    jcls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, jcls, "Argument cannot be null.");
    return (jlong) 0;
  }

  if(!(_bytes = (byte_t *) malloc(sizeof(byte_t)*size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jint) IERROR;
  }

  (*env)->GetByteArrayRegion(env, bytes, 0, size, (jbyte *) _bytes); 

  if(!(proof = groupsig_proof_import(code, _bytes, size))) {
    jcls = (*env)->FindClass(env, "java/lang/Exception");
    (*env)->ThrowNew(env, jcls, "Internal error.");
    return (jlong) 0;
  }
  free(_bytes); _bytes = NULL;
  return (jlong) proof;
  
}

static JNINativeMethod funcs_proof[] = {
  { "groupsig_proofInit", "(I)J", (void *) &groupsig_proofInit },
  { "groupsig_proofFree", "(J)I", (void *) &groupsig_proofFree },
  { "groupsig_proofGetCode", "(J)I", (void *) &groupsig_proofGetCode },
  { "groupsig_proofExport", "(J)[B", (void *) &groupsig_proofExport },
  { "groupsig_proofImport", "(I[BI)J", (void *) &groupsig_proofImport },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {

  JNIEnv *env;
  jclass  cls_gl19;
  jclass  cls_bbs04;
  jclass  cls_ps16;  
  jclass  cls_grpkey;
  jclass  cls_mgrkey;
  jclass  cls_memkey;
  jclass  cls_bldkey;
  jclass  cls_identity;    
  jclass  cls_gml;
  jclass  cls_signature;
  jclass  cls_blindsig;
  jclass  cls_proof;  
  jint    res;

  (void)reserved;

  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8) != JNI_OK)
    return -1;

  /* Register GL19 */
  cls_gl19 = (*env)->FindClass(env, JNIT_CLASS_GL19);
  if (cls_gl19 == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_GL19);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_gl19, funcs_gs, sizeof(funcs_gs)/sizeof(*funcs_gs));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_GL19);
    return -1;
  }

  /* Register BBS04 */
  cls_bbs04 = (*env)->FindClass(env, JNIT_CLASS_BBS04);
  if (cls_bbs04 == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_BBS04);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_bbs04, funcs_gs, sizeof(funcs_gs)/sizeof(*funcs_gs));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_BBS04);
    return -1;
  }

  /* Register PS16 */
  cls_ps16 = (*env)->FindClass(env, JNIT_CLASS_PS16);
  if (cls_ps16 == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_PS16);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_ps16, funcs_gs, sizeof(funcs_gs)/sizeof(*funcs_gs));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_PS16);
    return -1;
  }  
  

  /* Register GrpKey */
  cls_grpkey = (*env)->FindClass(env, JNIT_CLASS_GRPKEY);
  if (cls_grpkey == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_GRPKEY);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_grpkey, funcs_grpkey, sizeof(funcs_grpkey)/sizeof(*funcs_grpkey));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_GRPKEY);
    return -1;
  }
  
  /* Register MgrKey */
  cls_mgrkey = (*env)->FindClass(env, JNIT_CLASS_MGRKEY);
  if (cls_mgrkey == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_MGRKEY);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_mgrkey, funcs_mgrkey, sizeof(funcs_mgrkey)/sizeof(*funcs_mgrkey));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_MGRKEY);
    return -1;
  }
  
  /* Register MemKey */
  cls_memkey = (*env)->FindClass(env, JNIT_CLASS_MEMKEY);
  if (cls_memkey == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_MEMKEY);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_memkey, funcs_memkey, sizeof(funcs_memkey)/sizeof(*funcs_memkey));
  if (res != 0)
    return -1;

  /* Register BlindKey */
  cls_bldkey = (*env)->FindClass(env, JNIT_CLASS_BLDKEY);
  if (cls_bldkey == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_BLDKEY);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_bldkey, funcs_bldkey, sizeof(funcs_bldkey)/sizeof(*funcs_bldkey));
  if (res != 0)
    return -1;

  /* Register Identity */
  cls_identity = (*env)->FindClass(env, JNIT_CLASS_IDENTITY);
  if (cls_identity == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_IDENTITY);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_identity, funcs_identity, sizeof(funcs_identity)/sizeof(*funcs_identity));
  if (res != 0)
    return -1;
  
  /* Register Gml */
  cls_gml = (*env)->FindClass(env, JNIT_CLASS_GML);
  if (cls_gml == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_GML);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_gml, funcs_gml, sizeof(funcs_gml)/sizeof(*funcs_gml));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_GML);
    return -1;
  }

  /* Register Signature */
  cls_signature = (*env)->FindClass(env, JNIT_CLASS_SIGNATURE);
  if (cls_signature == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_SIGNATURE);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_signature, funcs_signature, sizeof(funcs_signature)/sizeof(*funcs_signature));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_SIGNATURE);
    return -1;
  }

  /* Register Blindsig */
  cls_blindsig = (*env)->FindClass(env, JNIT_CLASS_BLINDSIG);
  if (cls_blindsig == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_BLINDSIG);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_blindsig, funcs_blindsig, sizeof(funcs_blindsig)/sizeof(*funcs_blindsig));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_BLINDSIG);
    return -1;
  }

  /* Register Proof */
  cls_proof = (*env)->FindClass(env, JNIT_CLASS_PROOF);
  if (cls_proof == NULL) {
    fprintf(stderr, "Error finding %s\n", JNIT_CLASS_PROOF);
    return -1;
  }

  res = (*env)->RegisterNatives(env, cls_proof, funcs_proof, sizeof(funcs_proof)/sizeof(*funcs_proof));
  if (res != 0) {
    fprintf(stderr, "Error registering natives for %s\n", JNIT_CLASS_PROOF);
    return -1;
  }  

  return JNI_VERSION_1_8;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
  
  JNIEnv *env;
  jclass cls_gl19;
  jclass cls_bbs04;
  jclass cls_ps16;  
  jclass cls_grpkey;
  jclass cls_mgrkey;
  jclass cls_memkey;
  jclass cls_bldkey;
  jclass cls_identity;
  jclass cls_gml;
  jclass cls_signature;
  jclass cls_blindsig;
  jclass cls_proof;
  
  (void)reserved;

  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8) != JNI_OK)
    return;

  /* GL19 */
  cls_gl19 = (*env)->FindClass(env, JNIT_CLASS_GL19);
  if (cls_gl19 == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_gl19);

  /* BBS04 */
  cls_bbs04 = (*env)->FindClass(env, JNIT_CLASS_BBS04);
  if (cls_bbs04 == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_bbs04);

  /* PS16 */
  cls_ps16 = (*env)->FindClass(env, JNIT_CLASS_PS16);
  if (cls_ps16 == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_ps16);  

  /* GRPKEY */
  cls_grpkey = (*env)->FindClass(env, JNIT_CLASS_GRPKEY);
  if (cls_grpkey == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_grpkey);

  /* MGRKEY */
  cls_mgrkey = (*env)->FindClass(env, JNIT_CLASS_MGRKEY);
  if (cls_mgrkey == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_mgrkey);

  /* MEMKEY */
  cls_memkey = (*env)->FindClass(env, JNIT_CLASS_MEMKEY);
  if (cls_memkey == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_memkey);

  /* BLDKEY */
  cls_bldkey = (*env)->FindClass(env, JNIT_CLASS_BLDKEY);
  if (cls_bldkey == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_bldkey);

  /* IDENTITY */
  cls_identity = (*env)->FindClass(env, JNIT_CLASS_IDENTITY);
  if (cls_identity == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_identity);
  
  /* GML */
  cls_gml = (*env)->FindClass(env, JNIT_CLASS_GML);
  if (cls_gml == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_gml);

  /* SIGNATURE */
  cls_signature = (*env)->FindClass(env, JNIT_CLASS_SIGNATURE);
  if (cls_signature == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_signature);

  /* BLINDSIG */
  cls_blindsig = (*env)->FindClass(env, JNIT_CLASS_BLINDSIG);
  if (cls_blindsig == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_blindsig);

  /* PROOF */
  cls_proof = (*env)->FindClass(env, JNIT_CLASS_PROOF);
  if (cls_proof == NULL)
    return;

  (*env)->UnregisterNatives(env, cls_proof);
  
  
}
