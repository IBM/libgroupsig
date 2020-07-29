package com.ibm.jgroupsig;

import java.util.Base64;

/**
 * Class for Group Keys in the groupsig package.
 * 
 * Offers several interfaces to create and operate with group keys.
 * It is part of the groupsig package.
 */
public class GrpKey {

    /**
     * The GS scheme code.
     */    
    private int code = -1;

    /**
     * The internal JNI pointer.
     */    
    private long ptr = 0;

    public GrpKey() {}

    /**
     * Creates a new instance of group key for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public GrpKey(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_grpKeyInit(code);
	return;
    }

    /**
     * Creates a new instance of group key for the given scheme, importing
     * the key material from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported group key.
     * @exception IllegalArgumentException
     * @exception Exception
     */     
    public GrpKey(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_grpKeyImport(code, b, b.length);
	this.code = code;
    }

    /**
     * Frees the memory allocated for the current blinding key instance.
     */    
    protected void finalize() {
	groupsig_grpKeyFree(this.ptr);
    }

    /**
     * Exports this instance of a group key (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_grpKeyExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }   

    /**
     * Returns the pointer of the internal JNI object for this key.
     * 
     * @return A pointer to the internal JNI object for this key.
     */    
    public long getObject() { return ptr; }

    /**
     * Returns the code for this key's scheme.
     *
     * @return The key scheme.
     */
    public int getCode() { return this.code; }

    static { System.loadLibrary("jnigroupsig"); }
    
    private static native long groupsig_grpKeyInit(int code);
    private static native int groupsig_grpKeyFree(long ptr);
    private static native int groupsig_grpKeyGetCode(long ptr);
    private static native byte[] groupsig_grpKeyExport(long ptr);
    private static native long groupsig_grpKeyImport(int code, byte[] b, int size);
    
}
