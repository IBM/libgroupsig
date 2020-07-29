package com.ibm.jgroupsig;

/**
 * Class for Group Membership Lists (GMLs) in the groupsig package.
 * 
 * Offers several interfaces to create and operate with GMLs.
 * It is part of the groupsig package.
 */
public class Gml {

    /**
     * The GS scheme code.
     */
    private int code = -1;

    /**
     * The internal JNI pointer.
     */
    private long ptr = 0;

    public Gml() {}

    /**
     * Creates a new instance of GML (Group Membership List) for the given 
     * scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public Gml(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_gmlInit(code);
	return;
    }

    /**
     * Frees the memory allocated for the current signature instance.
     */    
    protected void finalize() {
	groupsig_gmlFree(this.ptr);
    }

    /**
     * Returns the pointer of the internal JNI object for this signature.
     * 
     * @return A pointer to the internal JNI object for this signature.
     */    
    public long getObject() { return ptr; }

    /**
     * Returns the code for this GML's scheme.
     *
     * @return The GML scheme.
     */
    public int getCode() { return this.code; }      
    
    static { System.loadLibrary("jnigroupsig"); }
    
    private static native long groupsig_gmlInit(int code);
    private static native int groupsig_gmlFree(long ptr);
    
}
