package com.ibm.jgroupsig;

import java.util.Base64;

/**
 * Class for Blinding Keys in the groupsig package.
 * 
 * Offers several interfaces to create and operate with blinding keys.
 * It is part of the groupsig package.
 */
public class BldKey {

    /**
     * The GS scheme code.
     */    
    private int code = -1;

    /**
     * The internal JNI pointer.
     */    
    private long ptr = 0;

    public BldKey() {}

    /**
     * Creates a new instance of blinding key for the given scheme.
     *
     * @param code The code identifying the GS scheme.
     * @exception IllegalArgumentException
     * @exception Exception
     */   
    public BldKey(int code)
	throws IllegalArgumentException,
	       Exception
    {
	this.code = code;
	this.ptr = groupsig_bldKeyInit(code);
	return;
    }

    /**
     * Creates a new instance of blinding key for the given scheme, importing
     * the key material from the given string. Works both for full blinding keys
     * (including public and private parts) and public blinding keys.
     *
     * @param code The code identifying the GS scheme.
     * @param str A string containing a previously exported blinding key.
     * @exception IllegalArgumentException
     * @exception Exception
     */
    public BldKey(int code, String str)
	throws IllegalArgumentException,
	       Exception	
    {
	byte[] b = Base64.getMimeDecoder().decode(str);
	this.ptr = groupsig_bldKeyImport(code, b, b.length);
	this.code = code;
    }

    /**
     * Frees the memory allocated for the current blinding key instance.
     */   
    protected void finalize() {
	groupsig_bldKeyFree(this.ptr);
    }

    /**
     * Initializes a new random blinding key for the given group and sets it to 
     * a random value.
     *
     * @param grpKey The group key (contains public parameters of the GS scheme).
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public static BldKey getRandom(int code, GrpKey grpKey)
	throws IllegalArgumentException,
	       Exception
    {
	BldKey key = new BldKey();
	long ptr = groupsig_bldKeyRandom(code, grpKey.getObject());
	key.setObject(ptr);
	key.setCode(code);
	return key;
    }

    /**
     * Exports this instance of a blinding key (currently, to a base64 string).
     * Exports both the public and private parts of the key.
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public String export()
	throws IllegalArgumentException,
	       Exception	
    {
	byte[] b = groupsig_bldKeyExport(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }

    /**
     * Exports the public part of this instance of a blinding key (currently, 
     * to a base64 string).
     *
     * @return A base64-encoded string.
     * @exception IllegalArgumentException
     * @exception Exception
     */    
    public String exportPub()
	throws IllegalArgumentException,
	       Exception	
    {
	byte[] b = groupsig_bldKeyExportPub(this.ptr);
	return Base64.getMimeEncoder().encodeToString(b);
    }
    

    /**
     * Returns the pointer of the internal JNI object for this key.
     * 
     * @return A pointer to the internal JNI object for this key.
     */
    public long getObject() { return ptr; }

    /**
     * Sets the pointer to the internal JNI object for this key.
     * @param The pointer to the internal JNI object.
     */
    public void setObject(long ptr) { this.ptr = ptr; }

    /**
     * Returns the code for this key's scheme.
     *
     * @return The key scheme.
     */
    public int getCode() { return this.code; }

    /**
     * Sets the current objects code to the given code.
     * @param code The code to set.
     */
    public void setCode(int code) { this.code = code; }

    static { System.loadLibrary("jnigroupsig"); }

    private static native long groupsig_bldKeyInit(int code);
    private static native int groupsig_bldKeyFree(long ptr);
    private static native long groupsig_bldKeyRandom(int code,
						     long grpKeyPtr);
    private static native int groupsig_bldKeyGetCode(long ptr);
    private static native byte[] groupsig_bldKeyExport(long ptr);
    private static native byte[] groupsig_bldKeyExportPub(long ptr);
    private static native long groupsig_bldKeyImport(int code, byte[] b, int size);
    
}
