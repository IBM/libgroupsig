package com.ibm.jgroupsig;

/**
 * Class for identities in the groupsig package.
 * 
 * Offers several interfaces to create and operate with identities.
 * It is part of the groupsig package.
 */
public class IdProof {

    /**
     * The GS scheme code.
     */        
    private int code = -1;

    /**
     * The identity object.
     */        
    private Identity id = null;

    /**
     * The proof object.
     */        
    private Proof proof = null;

    public IdProof() {}

    /**
     * Creates a new instance of IdProof for the given scheme, wrapping
     * the specified Identity and Proof objects.
     *
     * @param id The identity to add to the wrapper object.
     * @param proof The proof to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IdProof(Identity id, Proof proof)
	throws IllegalArgumentException,
	       Exception
    {
	if (id.getCode() != proof.getCode()) {
	    throw new IllegalArgumentException("Invalid code.");
	}
	    
	this.code = id.getCode();
	this.id = id;
	this.proof = proof;
	return;
    }

    /**
     * Creates a new instance of IdProof for the given scheme, using.
     * the specified Identity object and setting the internal proof to null.
     *
     * @param id The identity to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IdProof(Identity id)
	throws IllegalArgumentException,
	       Exception
    {    
	this.code = id.getCode();
	this.id = id;
	return;
    }

    /**
     * Creates a new instance of IdProof for the given scheme, using.
     * the specified Identity object and setting the internal proof to null.
     *
     * @param proof The proof to add to the wrapper object.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public IdProof(Proof proof)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = proof.getCode();
	this.proof = proof;
	return;
    }        

    /**
     * Frees the memory allocated for the current IdProof.
     */     
    protected void finalize() {
	groupsig_identityFree(this.id.getObject());
	groupsig_proofFree(this.proof.getObject());	
    }

    /**
     * Returns the code for this identity's scheme.
     *
     * @return The identity scheme.
     */
    public int getCode() { return this.code; }

    /**
     * Returns the internal identity object.
     *
     * @return The identity object.
     */
    public Identity getIdentity() { return this.id; }

    /**
     * Returns the internal rpoof object.
     *
     * @return The proof object.
     */
    public Proof getProof() { return this.proof; }    

    static { System.loadLibrary("jnigroupsig"); }

    private static native int groupsig_identityFree(long ptr);
    private static native int groupsig_proofFree(long ptr);
    
}
