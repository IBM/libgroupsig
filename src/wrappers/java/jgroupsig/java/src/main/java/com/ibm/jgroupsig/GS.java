package com.ibm.jgroupsig;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.lang.Exception;

/**
 * Interface for Group Signature schemes.
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
public interface GS {

    /**
     * Code for instances corresponding to the BBS04 group signature scheme.
     */
    public static final int BBS04_CODE = 1;

    /**
     * Name for the instances corresponding to the BBS04 group signature scheme.
     */
    public static final String BBS04_STR = "BBS04";

    /**
     * Code for instances corresponding to the GL19 group signature scheme.
     */
    public static final int GL19_CODE = 3;

    /**
     * Name for the instances corresponding to the GL19 group signature scheme.
     */
    public static final String GL19_STR = "GL19";

    /**
     * Code for instances corresponding to the PS16 group signature scheme.
     */
    public static final int PS16_CODE = 4;

    /**
     * Name for the instances corresponding to the PS16 group signature scheme.
     */
    public static final String PS16_STR = "PS16";    

    /**
     * Frees the memory internally allocated for the current GS instance.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public void finalize() throws IllegalArgumentException, Exception;

    /**
     * Prints "Hello, World!" in the standard output.
     */    
    public void helloWorld();

    /**
     * Returns True if the scheme identified by the given integer code is supported.
     * False if not.
     *
     * @param  code  The integer code identifying the scheme to test.
     * @return      True or False.
     * @exception IllegalArgumentException
     */        
    public boolean isSupportedScheme(int code)
	throws IllegalArgumentException;

    /**
     * Frees the memory internally allocated for the current GS instance.
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */ 
    public int clear() throws IllegalArgumentException, Exception;

    /**
     * Returns True if the current instance corresponds to a scheme that needs a
     * Group Membership List. False if not.
     *
     * @return True or False.
     */    
    public boolean hasGml();

    /**
     * Initializes the class attributes. Namely, the group key, the manager key,
     * and, if needed, the Group Membership List (GML).
     *
     * @exception IllegalArgumentException
     * @exception Exception
     */   
    public void setup()	throws IllegalArgumentException, Exception;

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
    public int getJoinSeq() throws IllegalArgumentException, Exception;

    /**
     * Returns who initiates the membership credential issuance protocol in this
     * instance (of a group signature scheme).
     *
     * @return 1 if the prospective member begins, 0 if the Issuer begins.
     * @exception IllegalArgumentException
     * @exception Exception
     * @see com.ibm.jgroupsig.GS#getJoinSeq
     */   
    public int getJoinStart() throws IllegalArgumentException, Exception;

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
    public long joinMem(MemKey memKey, int seq, long min)
	throws IllegalArgumentException, Exception;

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
    public long joinMgr(int seq, long min)
	throws IllegalArgumentException, Exception;

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
     public Signature sign(byte[] msg, MemKey memKey)
	 throws IllegalArgumentException, Exception;

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
    public Signature sign(byte[] msg, MemKey memKey, int s)
	throws IllegalArgumentException, Exception;

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
    public Signature sign(String msg, MemKey memKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;

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
    public Signature sign(String msg, MemKey memKey, int s)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;

    /**
     * Verifies if sig is a valid signature for the byte array msg.
     *
     * @param sig The signature instance.
     * @param msg The message, in byte array format.
     * @return True if the signature is valid, False otherwise.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public boolean verify(Signature sig, byte[] msg)
	throws IllegalArgumentException, Exception;

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
    public boolean verify(Signature sig, String msg)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;

    /**
     * Opens the given signature.
     *
     * @param sig The signature to open.
     * @return An object wrapping the index of the signer and, optionally,
     *  a proof of opening (for schemes that support it).
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */
    public IndexProof open(Signature sig)
	throws IllegalArgumentException,
	       Exception;

    /**
     * Verifies an opening of a signature.
     *
     * @param indexProof The object wrapping the signer index and opening 
     *  proof object.
     * @param sig The signature to open.
     * @return True if the proof is valid, False otherwise.
     * @exception UnsupportedEncodingException
     * @exception IllegalArgumentException
     * @exception Exception
     */
    public boolean openVerify(IndexProof indexProof, Signature sig)
	throws IllegalArgumentException,
	       Exception;    

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
    public BlindSignature blind(BldKey bldKey, Signature sig, String msg)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;

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
    public BlindSignature blind(BldKey bldKey, Signature sig, byte[] msg)
	throws IllegalArgumentException,
	       Exception;

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
    public BlindSignature[] convert(BlindSignature[] bSigs, BldKey bldKey)
	throws IllegalArgumentException,
	       Exception;

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
    public Identity unblind(BlindSignature cSig, BldKey bldKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;

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
    public Identity unblind(Signature sig, BlindSignature cSig, BldKey bldKey)
	throws UnsupportedEncodingException,
	       IllegalArgumentException,
	       Exception;
    
    /**
     * Returns the code of the current GS instance.
     *
     * @return The code of the current GS instance.
     */         
    public int getCode();

    /**
     * Returns the internal native pointer to the current GS instance.
     *
     * @return The pointer to the current GS instance.
     */         
    public long getGroup();

}
