package com.ibm.jgroupsig;

import java.util.Base64;

/**
 * Class for Blind Signatures in the groupsig package.
 * 
 * Offers several interfaces to create and operate with blinded group signatures.
 * It is part of the groupsig package.
 */
public class BlindSignature {

    /**
     * The GS scheme code.
     */    
    private int code = -1;

    /**
     * The internal JNI pointer.
     */    
    private long ptr = 0;

    public BlindSignature() {}

        /**
     * Creates a new instance of blind signature for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public BlindSignature(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_blindSignatureInit(code);
	return;
    }

    /**
     * Creates a new instance of blind signature for the given scheme, importing
     * the signature data from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported blind signature.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public BlindSignature(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_blindSignatureImport(code, b, b.length); 
	this.code = code;
    }        

    /**
     * Frees the memory allocated for the current blind signature.
     */    
    protected void finalize() {
	groupsig_blindSignatureFree(this.ptr);
    }

    /**
     * Exports this instance of a blind signature (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_blindSignatureExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }    

    /**
     * Returns the pointer of the internal JNI object for this blind signature.
     * 
     * @return A pointer to the internal JNI object for this blind signature.
     */    
    public long getObject() { return ptr; }

    /**
     * Sets the pointer of the internal JNI object for this blind signature.
     */    
    public void setObject(long ptr) { this.ptr = ptr; }    

    /**
     * Returns the code for this signature's scheme.
     *
     * @return The signature scheme.
     */
    public int getCode() { return this.code; }        

    static { System.loadLibrary("jnigroupsig"); }
    
    private static native long groupsig_blindSignatureInit(int code);
    private static native int groupsig_blindSignatureFree(long ptr);
    private static native int groupsig_blindSignatureGetCode(long ptr);
    private static native byte[] groupsig_blindSignatureExport(long ptr);
    private static native long groupsig_blindSignatureImport(int code, byte[] b, int size);

}
