package com.ibm.jgroupsig;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * Class for Manager Keys in the groupsig package.
 * 
 * Offers several interfaces to create and operate with group manager keys.
 * It is part of the groupsig package.
 */
public class MgrKey {
    /**
     * The GS scheme code.
     */
    private int code = -1;
 
    /**
     * The internal JNI pointer.
     */   
    private long ptr = 0;

    public MgrKey() {}

    /**
     * Creates a new instance of manager key for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public MgrKey(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_mgrKeyInit(code);
	return;
    }

    /**
     * Creates a new instance of manager key for the given scheme, importing
     * the key material from the given string.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported manager key.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public MgrKey(int code, String str)
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_mgrKeyImport(code, b, b.length);
	this.code = code;
    }    

    /**
     * Frees the memory allocated for the current blinding key instance.
     */       
    protected void finalize() {
	groupsig_mgrKeyFree(this.ptr);
    }

    /**
     * Exports this instance of a manager key (currently, to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */       
    public String export()
	throws IllegalArgumentException,
	       Exception
    {
	byte[] b = groupsig_mgrKeyExport(this.ptr);
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

    private static native long groupsig_mgrKeyInit(int code);
    private static native int groupsig_mgrKeyFree(long ptr);
    private static native int groupsig_mgrKeyGetCode(long ptr);
    private static native byte[] groupsig_mgrKeyExport(long ptr);
    private static native long groupsig_mgrKeyImport(int code, byte[] b, int size);
    
    
}
