package com.ibm.jgroupsig;

import java.util.Base64;

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
     * Creates a new instance of gml for the given scheme, importing
     * the gml data from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported gml.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public Gml(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_gmlImport(code, b, b.length); 
	this.code = code;
    }        

    /**
     * Exports this instance of a GML (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_gmlExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }     

    /**
     * Frees the memory allocated for the current gml instance.
     */    
    protected void finalize() {
	groupsig_gmlFree(this.ptr);
    }

    /**
     * Returns the pointer of the internal JNI object for this gml.
     * 
     * @return A pointer to the internal JNI object for this gml.
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
    private static native byte[] groupsig_gmlExport(long ptr);
    private static native long groupsig_gmlImport(int code, byte[] b, int size);    
}
