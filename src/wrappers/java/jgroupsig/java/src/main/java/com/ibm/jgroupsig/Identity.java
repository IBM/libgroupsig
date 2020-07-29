package com.ibm.jgroupsig;

/**
 * Class for identities in the groupsig package.
 * 
 * Offers several interfaces to create and operate with identities.
 * It is part of the groupsig package.
 */
public class Identity {

    /**
     * The GS scheme code.
     */        
    private int code = -1;

    /**
     * The internal JNI pointer.
     */        
    private long ptr = 0;

    /**
     * The message associated to this identity. Can be null.
     */        
    private byte[] msg;

    public Identity() {}

    /**
     * Creates a new instance of Identity (pseudonym) for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public Identity(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_identityInit(code);
	this.msg = null;
	return;
    }

    /**
     * Frees the memory allocated for the current Identity.
     */     
    protected void finalize() {
	groupsig_identityFree(this.ptr);
    }

    /**
     * Produces a printable string corresponding to the pseudonym in this Identity.
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public String toStr()
	throws IllegalArgumentException,
	       Exception
    {
	return groupsig_identityToString(this.ptr);
    }

    /**
     * Overloaded equality operator.
     *
     * The comparison does not consider the msg attribute, even when present.
     *
     * @return True if both identities are the same, false if not.
     */
    public boolean equals(Identity id)
	throws Exception {
	return this.toStr().equals(id.toStr());
    }

    /**
     * For identities that also have an associated message, sets the message to 
     * the given byte array.
     *
     * @param msg The message to associate to the current identity.
     */    
    public void setMsg(byte[] msg) {
	this.msg = msg;
    }

    /**
     * For identities that also have an associated message, returns the message
     * associated to the current identity.
     *
     * @return The message associated to the current identity, or null if there 
     *  is none.
     */        
    public byte[] getMsg() {
	return this.msg;
    }

    /**
     * Returns the pointer of the internal JNI object for this Identity.
     * 
     * @return A pointer to the internal JNI object for this Identity.
     */      
    public long getObject() { return ptr; }

    /**
     * Returns the code for this identity's scheme.
     *
     * @return The identity scheme.
     */
    public int getCode() { return this.code; }        

    static { System.loadLibrary("jnigroupsig"); }

    private static native long groupsig_identityInit(int code);
    private static native int groupsig_identityFree(long ptr);
    private static native String groupsig_identityToString(long ptr);
    
}
