package com.ibm.jgroupsig;

/**
 * Class for identities in the groupsig package.
 * 
 * Offers several interfaces to create and operate with identities.
 * It is part of the groupsig package.
 */
public class IndexProof {

    /**
     * The GS scheme code.
     */        
    private int code = -1;

    /**
     * The index of the signer within a GML.
     */
    private long index = -1;

    /**
     * The proof object.
     */        
    private Proof proof = null;

    public IndexProof() {}

    /**
     * Creates a new instance of IndexProof for the given scheme, wrapping
     * the specified index and Proof object.
     *
     * @param index The index to add to the wrapper object.
     * @param proof The proof to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IndexProof(long index, Proof proof)
	throws IllegalArgumentException,
	       Exception
    {
    
	this.code = proof.getCode();
	this.index = index;
	this.proof = proof;
	return;
    }

    /**
     * Creates a new instance of IndexProof for the given scheme, using.
     * the specified index and setting the internal proof to null.
     *
     * @param index The index to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IndexProof(int code, long index)
	throws IllegalArgumentException,
	       Exception
    {    
	this.code = code;
	this.index = index;
	return;
    }

    /**
     * Creates a new instance of IndexProof for the given scheme, using.
     * the specified Identity object and setting the internal proof to null.
     *
     * @param proof The proof to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IndexProof(Proof proof)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = proof.getCode();
	this.proof = proof;
	return;
    }        

    /**
     * Frees the memory allocated for the current IndexProof.
     */     
    protected void finalize() {
	groupsig_proofFree(this.proof.getObject());	
    }

    /**
     * Returns the code for this identity's scheme.
     *
     * @return The identity scheme.
     */
    public int getCode() { return this.code; }

    /**
     * Returns the internal index
     *
     * @return The index.
     */
    public long getIndex() { return this.index; }

    /**
     * Returns the internal rpoof object.
     *
     * @return The proof object.
     */
    public Proof getProof() { return this.proof; }    

    static { System.loadLibrary("jnigroupsig"); }

    private static native int groupsig_proofFree(long ptr);
    
}
