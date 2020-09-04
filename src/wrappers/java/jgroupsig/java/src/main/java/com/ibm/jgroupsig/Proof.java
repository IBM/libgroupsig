package com.ibm.jgroupsig;

import java.util.Base64;

/**
 * Class for Proofs in the groupsig package.
 * 
 * Offers several interfaces to create and operate with group proofs.
 * It is part of the groupsig package.
 */
public class Proof {

    /**
     * The GS scheme code.
     */    
    private int code = -1;

    /**
     * The internal JNI pointer.
     */        
    private long ptr = 0;

    public Proof() {}

    /**
     * Creates a new instance of proof for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public Proof(int code)
	throws IllegalArgumentException,
	       Exception	
    {
	this.code = code;
	this.ptr = groupsig_proofInit(code);
	return;
    }

    /**
     * Creates a new instance of proof for the given scheme, importing
     * the proof data from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported proof.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public Proof(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_proofImport(code, b, b.length);
	this.code = code;
    }    

    /**
     * Frees the memory allocated for the current proof instance.
     */        
    protected void finalize() {
	groupsig_proofFree(this.ptr);
    }

    /**
     * Exports this instance of a proof (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_proofExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }    

    /**
     * Returns the pointer of the internal JNI object for this proof.
     * 
     * @return A pointer to the internal JNI object for this proof.
     */      
    public long getObject() { return ptr; }

    /**
     * Returns the code for this proof's scheme.
     *
     * @return The proof scheme.
     */
    public int getCode() { return this.code; }    

    static { System.loadLibrary("jnigroupsig"); }
    
    private static native long groupsig_proofInit(int code);
    private static native int groupsig_proofFree(long ptr);
    private static native int groupsig_proofGetCode(long ptr);
    private static native byte[] groupsig_proofExport(long ptr);
    private static native long groupsig_proofImport(int code, byte[] b, int size);

}
