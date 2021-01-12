package com.ibm.jgroupsig;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.lang.Exception;

/**
 * Class for GL19 Group Signature schemes.
 * 
 * Offers several interfaces to create and operate with group signatures schemes.
 * It is part of the groupsig package.
 *
 * @see com.ibm.jgroupsig.GrpKey
 * @see com.ibm.jgroupsig.MgrKey
 * @see com.ibm.jgroupsig.MemKey
 * @see com.ibm.jgroupsig.BldKey
 * @see com.ibm.jgroupsig.Gml
 * @see com.ibm.jgroupsig.Identity
 * @see com.ibm.jgroupsig.BlindSignature
 * @see com.ibm.jgroupsig.Signature
 */
public class GL19 implements GS {

    /**
     * The GS scheme code.
     */
    public int code = -1;

    /**
     * The internal JNI pointer.
     */
    public long ptr = 0;

    /**
     * The group key for this GS instance.
     */
    private GrpKey grpKey = null;

    /**
     * GL19 uses two manager keys.
     */
    private MgrKey[] mgrKey = null;
    
    /**
     * An alias to mgrkey[0]
     */
    private MgrKey issKey = null;

    /**
     * An alias to mgrkey[1]
     */    
    private MgrKey cnvKey = null;

    /**
     * The GML for this GS instance. Can be null.
     */
    public Gml gml = null;    

    /**
     * Returns a GL19 instance.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public GL19()
	throws IllegalArgumentException,
	       Exception
    {
	this.code = GS.GL19_CODE;
	this.ptr = groupsig_gsGetFromCode(this.code);
	groupsig_gsInit(this.code, 0);
    	this.mgrKey = new MgrKey[2];	
    }

    /**
     * Frees the memory internally allocated for the current GL19 instance.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override
    public void finalize()
	throws IllegalArgumentException,
	       Exception
    {
	this.clear();
    }

    /**
     * Frees the memory internally allocated for the current GL19 instance.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public int clear()
	throws IllegalArgumentException,
	       Exception
    {
	return groupsig_gsClear(this.code);
    }

    /**
     * Prints "Hello, World!" in the standard output.
     */
    @Override    
    public void helloWorld() {
	groupsig_gsHelloWorld();
	return;
    }

    /**
     * Returns True if the scheme identified by the given integer code is supported.
     * False if not.
     *
     * @param  code  The integer code identifying the scheme to test.
     * @return      True or False.
     * @exception IllegalArgumentException
     */
    @Override    
    public boolean isSupportedScheme(int code)
	throws IllegalArgumentException
    {
	return groupsig_gsIsSupportedScheme(code);
    }    

    /**
     * Returns True if the current instance corresponds to a scheme that needs a
     * Group Membership List. False if not.
     *
     * @return True or False.
     */    
    public boolean hasGml() {
	return groupsig_gsHasGml(this.code);
    }

    /**
     * Runs the first step of the GL19 setup process. As a result of a call to 
     * this method, the grpkey attribute of the current GL19 instance is 
     * partially filled, and the isskey attribute (which is an alias to 
     * mgrkey[0]), is also initialied. If grpkey or isskey are not null, they
     * will be overwritten.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override
    public void setup()
    	throws IllegalArgumentException,
    	       Exception
    {

	long gmlPtr;
	
    	this.grpKey = new GrpKey(this.code);
	this.mgrKey[0] = new MgrKey(this.code);
	this.gml = null;
	gmlPtr = 0;
	
    	groupsig_gsSetup(this.code,
			 this.grpKey.getObject(),
			 this.mgrKey[0].getObject(),
			 0);
	this.issKey = this.mgrKey[0];
	return;
    }

    /**
     * Completes the setup process of a GL19 group. The behaviour will depend on
     * the input parameters and the internal state of the present instance:
     * 
     * - If this.grpKey == null and grpKey != null, this is interpreted as a 
     *   call to setup the Converter. Thus, this.cnvKey = this.mgrKey[1] will
     *   be initialized properly, and this.grpKey will be set to an upadted 
     *   (fulfilled) version of grpKey (including the Converter's public key.)
     *
     * - If this.grpKey != null and grpKey != null and this.issKey != null, this
     *   is interpreted as the final call to the Issuer. Thus, this.grpKey is
     *   reset to the received grpKey instance.
     *
     * @param grpKey The group key to initialize/update as described above.
     * @exception IllegalArgumentException
     * @exception Exception
     */
    public void setup(GrpKey grpKey)
	throws IllegalArgumentException,
    	       Exception
    {

	/* If this.grpKey == null, then this is a call to the Converter. */
	if (this.grpKey == null && grpKey != null) {
	    this.grpKey = grpKey;
	    if (this.mgrKey[1] == null) this.mgrKey[1] = new MgrKey(this.code);

	    groupsig_gsSetup(this.code,
			     this.grpKey.getObject(),
			     this.mgrKey[1].getObject(),
			     0);
	    this.cnvKey = this.mgrKey[1];
	}

	
	/* If this.grpKey != null and this.issKey != null, then this is
	   the second call to the Issuer. Just update the group key. */
	else if (this.grpKey != null && grpKey != null && this.issKey != null) {
	    /* Free the "old" grpKey and make this.grpKey point to the
	       new one. */
	    this.grpKey = grpKey;
	}

	else {
	    throw new Exception("Unexpected parameters for GL19 setup.");
	}
	
    }

    /**
     * Returns the number of steps (between the Issuer and a prospective member)
     * needed to complete a membership credential issuance protocol.
     * 
     * E.g., a protocol with 4 steps, where the prospective Issuer is the initiator,
     * would be require the following chain of invocations: Issuer (joinMgr) - 
     * member (joinMem) - Issuer (joinMgr) - member (joinMem), with increasing
     * sequence numbers (0 to 3).
     *
     * @return      void.
     * @exception IllegalArgumentException
     * @exception Exception
     * @see com.ibm.jgroupsig.GS#getJoinStart
     */   
    @Override
    public int getJoinSeq()
	throws IllegalArgumentException,
	       Exception	
    {
	return groupsig_gsGetJoinSeq(this.code);
    }

    /**
     * Returns who initiates the membership credential issuance protocol in this
     * instance (of a group signature scheme).
     *
     * @return 1 if the prospective member begins, 0 if the Issuer begins.
     * @exception IllegalArgumentException
     * @exception Exception
     * @see com.ibm.jgroupsig.GS#getJoinSeq
     */   
    @Override
    public int getJoinStart()
	throws IllegalArgumentException,
	       Exception	
    {
	return groupsig_gsGetJoinStart(this.code);
    }

    /**
     * Runs the given sequence step of the member side in the membership 
     * credential issuance protocol.
     *
     * @param memKey The member key to setup.
     * @param seq The sequential step of the protocol to be executed.
     * @param min (A native pointer to) the message received from the Issuer in
     *  the previous step, or 0 if this is the first step in the protocol.
     * @return (A native pointer to) The message produced, which will need to be
     *  given to the Issuer in the next step (if any).
     * @exception IllegalArgumentException
     * @exception Exception
     * @see com.ibm.jgroupsig.GS#joinMgr
     */   
    @Override
    public long joinMem(MemKey memKey,
			int seq,
			long min)
	throws IllegalArgumentException,
	       Exception	
    {
	long mout;
	mout = groupsig_gsJoinMem(memKey.getObject(),
				  seq,
				  min,
				  this.grpKey.getObject());
	return mout;
    }

    /**
     * Runs the given sequence step of the Issuer side in the membership 
     * credential issuance protocol.
     *
     * @param seq The sequential step of the protocol to be executed.
     * @param min (A native pointer to) the message received from the member in
     *  the previous step, or 0 if this is the first step in the protocol.
     * @return (A native pointer to) The message produced, which will need to be
     *  given to the member in the next step (if any).
     * @exception IllegalArgumentException
     * @exception Exception
     * @see com.ibm.jgroupsig.GS#joinMem
     */
    @Override    
    public long joinMgr(int seq,
			long min)
	throws IllegalArgumentException,
	       Exception	
    {
	long mout;

	if (this.gml != null) {
	    mout = groupsig_gsJoinMgr(this.gml.getObject(),
				      this.issKey.getObject(),
				      seq,
				      min,
				      this.grpKey.getObject());
	} else {
	    mout = groupsig_gsJoinMgr(0,
				      this.issKey.getObject(),
				      seq,
				      min,
				      this.grpKey.getObject());

	}

	return mout;
    }

    /**
     * Signs the message defined by the given byte array, using the given member
     * key.
     *
     * @param msg An array of bytes to be signed.
     * @param memKey The member key to use for signing.
     * @return A new Signature instance with the produced signature.
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public Signature sign(byte[] msg,
			   MemKey memKey)
	 throws IllegalArgumentException,
		Exception	 
    {
	Signature sig = new Signature(this.code);
	if(groupsig_gsSign(sig.getObject(),
			   msg,
			   msg.length,
			   memKey.getObject(),
			   this.grpKey.getObject(),
			   0) == 1)
	    throw new Exception("Error signing.");
	return sig;
    }

    /**
     * Signs the message defined by the given byte array, using the given member
     * key.
     * Used in schemes that require additional input (e.g., s can be used to seed
     * a pseudo-random number generator or indicate state.)
     *
     * @param msg An array of bytes to be signed.
     * @param memKey The member key to use for signing.
     * @param s Additional input (scheme-dependent).
     * @return A new Signature instance with the produced signature.
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public Signature sign(byte[] msg,
			  MemKey memKey,
			  int s)
	throws IllegalArgumentException,
	       Exception
    {
	Signature sig = new Signature(this.code);
	if(groupsig_gsSign(sig.getObject(),
			   msg,
			   msg.length,
			   memKey.getObject(),
			   this.grpKey.getObject(),
			   s) == 1)
	    throw new Exception("Error signing.");
	return sig;
    }

    /**
     * Signs the message defined by the given String, using the given member
     * key. String is encoded as an utf8 byte array.
     *
     * @param msg The string to sign.
     * @param memKey The member key to use for signing.
     * @return A new Signature instance with the produced signature.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public Signature sign(String msg,
			  MemKey memKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception
    {

	Signature sig = new Signature(this.code);
	final byte[] utf8Bytes = msg.getBytes("UTF-8");
	if(groupsig_gsSign(sig.getObject(),
			   utf8Bytes,
			   utf8Bytes.length,
			   memKey.getObject(),
			   this.grpKey.getObject(),
			   0) == 1)
	    throw new Exception("Error signing.");
	return sig;
	
    }

    /**
     * Signs the message defined by the given String, using the given member
     * key. String is encoded as an utf8 byte array.
     * Used in schemes that require additional input (e.g., s can be used to seed
     * a pseudo-random number generator or indicate state.)
     *
     * @param msg The string to sign.
     * @param memKey The member key to use for signing.
     * @param s Additional input (scheme-dependent).
     * @return A new Signature instance with the produced signature.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public Signature sign(String msg,
			  MemKey memKey,
			  int s)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {

	Signature sig = new Signature(this.code);
	final byte[] utf8Bytes = msg.getBytes("UTF-8");
	if(groupsig_gsSign(sig.getObject(),
			   utf8Bytes,
			   utf8Bytes.length,
			   memKey.getObject(),
			   this.grpKey.getObject(),
			   s) == 1)
	    throw new Exception("Error signing.");
	return sig;
	
    }

    /**
     * Verifies if sig is a valid signature for the byte array msg.
     *
     * @param sig The signature instance.
     * @param msg The message, in byte array format.
     * @return True if the signature is valid, False otherwise.
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public boolean verify(Signature sig,
			  byte[] msg)
	throws IllegalArgumentException,
	       Exception
    {
	return groupsig_gsVerify(sig.getObject(),
				 msg,
				 msg.length,
				 this.grpKey.getObject());
    }

    /**
     * Verifies if sig is a valid signature for the String msg.
     *
     * @param sig The signature instance.
     * @param msg The message, in string format.
     * @return True if the signature is valid, False otherwise.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */
    @Override    
    public boolean verify(Signature sig,
			  String msg)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {
	
	final byte[] utf8Bytes = msg.getBytes("UTF-8");
	return groupsig_gsVerify(sig.getObject(),
				 utf8Bytes,
				 utf8Bytes.length,
				 this.grpKey.getObject());
	
    }

    public IndexProof open(Signature sig)
	throws IllegalArgumentException,
	       Exception {
	throw new Exception("Functionality not supported in GL19.");
    }

    public boolean openVerify(IndexProof indexProof,
			      Signature sig)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {
	throw new Exception("Functionality not supported in GL19.");		
    }      

    /**
     * For schemes supporting blinded conversion, encrypts the
     * given signature using bldkey.
     *
     * @param bldKey The blinding key to use for encryption.
     * @param sig The signature to blind.
     * @param msg The message, in string format.
     * @return The blinded signature.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    @Override
    public BlindSignature blind(BldKey bldKey,
				Signature sig,
				String msg)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {

	BlindSignature bSig = new BlindSignature(this.code);       
	final byte[] utf8Bytes = msg.getBytes("UTF-8");
	
	if(groupsig_gsBlind(bSig.getObject(),
			    bldKey.getObject(),
			    this.grpKey.getObject(),
			    sig.getObject(),
			    utf8Bytes,
			    utf8Bytes.length) == 1)
	    throw new Exception("Error blinding.");
	return bSig;
    }

    /**
     * For schemes supporting blinded conversion, encrypts the
     * given signature using bldkey.
     *
     * @param bldKey The blinding key to use for encryption.
     * @param sig The signature to blind.
     * @param msg The message, in string format.
     * @return The blinded signature.
     * @exception IllegalArgumentException
     * @exception Exception
     */           
    @Override
    public BlindSignature blind(BldKey bldKey,
				Signature sig,
				byte[] msg)
	throws IllegalArgumentException,
	       Exception
    {
	BlindSignature bSig = new BlindSignature(this.code);
	if(groupsig_gsBlind(bSig.getObject(),
			    bldKey.getObject(),
			    this.grpKey.getObject(),
			    sig.getObject(),
			    msg,
			    msg.length) == 1)
	    throw new Exception("Error blinding.");
	return bSig;
    }

    /**
     * For schemes supporting blinded conversion, converts the given
     * set of blinded signatures.
     *
     * @param bSigs The array of blinded signatures to convert.
     * @param bldKey The public key used for blinding.
     * @return An array containing the converted signatures.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    @Override
    public BlindSignature[] convert(BlindSignature[] bSigs,
				    BldKey bldKey)
	throws IllegalArgumentException,
	       Exception
    {	
	BlindSignature cSigs[] = new BlindSignature[bSigs.length];	
	long cSigsArray[] = new long[bSigs.length];
	long bSigsArray[] = new long[bSigs.length];

	for (int i=0; i<bSigs.length; i++) {
	    cSigs[i] = new BlindSignature(this.code);
	    cSigsArray[i] = cSigs[i].getObject();
	    bSigsArray[i] = bSigs[i].getObject();
	}
	
        if(groupsig_gsConvert(cSigsArray,
			      bSigsArray,
			      bSigs.length,
			      this.grpKey.getObject(),
			      this.cnvKey.getObject(),
			      bldKey.getObject(),
			      null,
			      0) == -1) {
	    throw new Exception("Error converting.");
	}

	for (int i=0; i<bSigs.length; i++) {
	    cSigs[i].setObject(cSigsArray[i]);
	}
	
	return cSigs;
    }    

    /**
     * For schemes supporting blinded conversion, unblinds the given
     * blindly converted signature.
     *
     * @param cSig The blindly converted signatures to unblind.
     * @param bldKey The keypair used for blinding.
     * @return The produced identity
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    @Override
    public Identity unblind(BlindSignature cSig,
			    BldKey bldKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {

	long grpKey;
	
	Identity id = new Identity(this.code);
	if (this.grpKey == null) grpKey = 0;
	else grpKey = this.grpKey.getObject();
	byte[] msg = groupsig_gsUnblind(id.getObject(),
					0,
					cSig.getObject(),
					grpKey,
					bldKey.getObject());

	if (msg == null) throw new Exception("Error unblinding.");
	if (msg != null) id.setMsg(msg);
	return id;
    }    

    /**
     * For schemes supporting blinded conversion, unblinds the given
     * blindly converted signature.
     *
     * @param sig The signature that was originally blinded.
     * @param cSig The blindly converted signatures to unblind.
     * @param bldKey The keypair used for blinding.
     * @return The produced identity.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    @Override
    public Identity unblind(Signature sig,
			    BlindSignature cSig,
			    BldKey bldKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception	       
    {

	Identity id = new Identity(this.code);
	byte[] msg = groupsig_gsUnblind(id.getObject(),
					sig.getObject(),
					cSig.getObject(),
					this.grpKey.getObject(),
					bldKey.getObject());

	if (msg == null) throw new Exception("Error unblinding.");
	if (msg != null) id.setMsg(msg);
	return id;
    }

    /**
     * Returns the group key of the current GL19 instance.
     *
     * @return The group key of the current GL19 instance.
     */     
    public GrpKey getGrpKey() {
	return this.grpKey;
    }

    /**
     * Sets the group's public key.
     * Warning: This should only be used on groups that have been initialized
     * but not setup.
     *
     * @param grpKey The group key to set.
     */
    public void setGrpKey(GrpKey grpKey) {
	this.grpKey = grpKey;
    }

    /**
     * Returns the manager key of the current GL19 instance.
     *
     * @return The manager keys of the current GL19 instance.
     */     
    public MgrKey[] getMgrKey() {
	return this.mgrKey;
    }

    /**
     * Sets the group's manager key.
     * Warning: This should only be used on groups that have been initialized
     * but not setup.
     *
     * @param mgrKey The manager keys to set.
     */
    public void setMgrKey(MgrKey[] mgrKey) {
	this.mgrKey = mgrKey;
    }

    /**
     * Returns the current instance's issuer key.
     *
     * @return The issuer key of the current GL19 instance.
     */
    public MgrKey getIssKey() {
	return this.issKey;
    }

    /**
     * Sets the group's issuer key.
     * Warning: This should only be used on groups that have been initialized
     * but not setup.
     *
     * @param issKey The manager key to set.
     */
    public void setIssKey(MgrKey issKey) {
	this.mgrKey[0] = issKey;
	this.issKey = issKey;
    }

    /**
     * Returns the current instance's converter key.
     *
     * @return The converter key of the current GL19 instance.
     */
    public MgrKey getCnvKey() {
	return this.cnvKey;
    }

    /**
     * Sets the group's converter key.
     * Warning: This should only be used on groups that have been initialized
     * but not setup.
     *
     * @param cnvKey The manager key to set.
     */
    public void setCnvKey(MgrKey cnvKey) {
	this.mgrKey[1] = cnvKey;
	this.cnvKey = cnvKey;
    }    
    
    /**
     * Returns the code of the current GL19 instance.
     *
     * @return The code of the current GL19 instance.
     */         
    @Override
    public int getCode() {
    	return this.code;
    }

    /**
     * Returns the internal native pointer to the current GL19 instance.
     *
     * @return The pointer to the current GL19 instance.
     */         
    @Override
    public long getGroup() {
    	return this.ptr;
    }

    static { System.loadLibrary("jnigroupsig"); }
    
    private static native int groupsig_gsHelloWorld();
    private static native boolean groupsig_gsIsSupportedScheme(int code);
    private static native int groupsig_gsGetCodeFromStr(String str);
    private static native long groupsig_gsGetFromStr(String str);
    private static native long groupsig_gsGetFromCode(int code);
    private static native int groupsig_gsInit(int code,
					      int seed);
    private static native int groupsig_gsClear(int code);
    private static native boolean groupsig_gsHasGml(int code);
    private static native int groupsig_gsSetup(int code,
    					       long grpKeyPtr,
    					       long mgrKeyPtr,
    					       long gmlPtr);
    private static native int groupsig_gsGetJoinSeq(int code);
    private static native int groupsig_gsGetJoinStart(int code);
    private static native long groupsig_gsJoinMem(long memKeyPtr,
    						  int seq,
    						  long minPtr,
    						  long grpKeyPtr);
    private static native long groupsig_gsJoinMgr(long gmlPtr,
    						  long mgrKeyPtr,
    						  int seq,
    						  long minPtr,
    						  long grpKeyPtr);
    private static native int groupsig_gsSign(long sigPtr,
    					      byte[] msg,
    					      int msgLen,
    					      long memKeyPtr,
    					      long grpKeyPtr,
    					      int seed);
    private static native boolean groupsig_gsVerify(long sigPtr,
    						    byte[] msg,
    						    int msgLen,
    						    long grpKeyPtr);
    private static native long groupsig_gsOpen(long proofPtr,
					       long crlPtr,
					       long sigPtr,
					       long grpKeyPtr,
					       long mgrKeyPtr,
					       long gmlPtr);
    private static native boolean groupsig_gsOpenVerify(long proofPtr,
							long sigPtr,
							long grpKeyPtr);        
    private static native int groupsig_gsBlind(long bSigPtr,
    					       long bldKeyPtr,
    					       long grpKeyPtr,
    					       long sigPtr,
    					       byte[] msg,
    					       int msgLen);
    private static native int groupsig_gsConvert(long[] cSigsPtr,
    						 long[] bSigsPtr,
    						 int bSigsLen,
    						 long grpKeyPtr,
    						 long mgrKeyPtr,
    						 long bldKeyPtr,
    						 byte[] msg,
    						 int msgLen);
    private static native byte[] groupsig_gsUnblind(long idPtr,
    						    long sigPtr,
    						    long bSigPtr,
    						    long grpKeyPtr,
    						    long bldKeyPtr);    

}
