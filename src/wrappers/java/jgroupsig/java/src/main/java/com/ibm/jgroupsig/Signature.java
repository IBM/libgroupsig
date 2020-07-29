package com.ibm.jgroupsig;

import java.util.Base64;

/**
 * Class for Signatures in the groupsig package.
 * 
 * Offers several interfaces to create and operate with group signatures.
 * It is part of the groupsig package.
 */
public class Signature {

    /**
     * The GS scheme code.
     */    
    private int code = -1;

    /**
     * The internal JNI pointer.
     */        
    private long ptr = 0;

    public Signature() {}

    /**
     * Creates a new instance of signature for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public Signature(int code)
	throws IllegalArgumentException,
	       Exception	
    {
	this.code = code;
	this.ptr = groupsig_signatureInit(code);
	return;
    }

    /**
     * Creates a new instance of signature for the given scheme, importing
     * the signature data from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported signature.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public Signature(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_signatureImport(code, b, b.length); 
	this.code = code;
    }    

    /**
     * Frees the memory allocated for the current signature instance.
     */        
    protected void finalize() {
	groupsig_signatureFree(this.ptr);
    }

    /**
     * Exports this instance of a signature (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_signatureExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }    

    /**
     * Returns the pointer of the internal JNI object for this signature.
     * 
     * @return A pointer to the internal JNI object for this signature.
     */      
    public long getObject() { return ptr; }

    /**
     * Returns the code for this signature's scheme.
     *
     * @return The signature scheme.
     */
    public int getCode() { return this.code; }    

    static { System.loadLibrary("jnigroupsig"); }
    
    private static native long groupsig_signatureInit(int code);
    private static native int groupsig_signatureFree(long ptr);
    private static native int groupsig_signatureGetCode(long ptr);
    private static native byte[] groupsig_signatureExport(long ptr);
    private static native long groupsig_signatureImport(int code, byte[] b, int size);

}
