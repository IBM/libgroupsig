package com.ibm.jgroupsig;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class GL19Test {

    /**
     * Will represent a GL19 group from the point of view of the Issuer. I.e.,
     * it has an initialized grpKey and issKey.
     */
    private GL19 groupIssuer = null;

    /**
     * Will represent a GL19 group from the point of view of the Converter. I.e.,
     * it has an initialized grpkey and cnvKey.
     */    
    private GL19 groupConverter = null;

    /**
     * Will represent a GL19 group from the point of view of a user. I.e.,
     * it has an initialized grpKey. When used to sign, member keys will be 
     * added.
     */    
    private GL19 groupUser = null;
    
    GL19Test() throws Exception {
	this.groupIssuer = new GL19();
	this.groupConverter = new GL19();
	this.groupUser = new GL19();
    }

    private MemKey addMember()
	throws IllegalArgumentException,
	       Exception
    {

	MemKey memkey = new MemKey(GS.GL19_CODE);

	long mout1 = this.groupIssuer.joinMgr(0, 0);
	if (mout1 == 0) {
	    return null;
	}

	long mout2 = this.groupUser.joinMem(memkey, 1, mout1);
	if (mout2 == 0) {
	    return null;
	}

	long mout3 = this.groupIssuer.joinMgr(2, mout2);
	if (mout3 == 0) {
	    return null;
	}

	this.groupUser.joinMem(memkey, 3, mout3);

	return memkey;
	
    }

    private void setupFull()
	throws IllegalArgumentException,
	       Exception
    {
	this.groupIssuer.setup();
	this.groupConverter.setup(this.groupIssuer.getGrpKey());
	this.groupIssuer.setup(this.groupConverter.getGrpKey());
	this.groupUser.setGrpKey(this.groupIssuer.getGrpKey());
    }
    
    @Test
    public void creationOfGroupShouldSetInternalAttributes() {

        // assert statements
        assertTrue(this.groupIssuer.getCode() == GS.GL19_CODE,
		   "Unexpected group code.");
	assertTrue(this.groupIssuer.getGroup() != 0,
		   "Unexpected group structure.");	
    }

    @Test
    public void setupCreatesGrpAndMgrKeys()
    	throws Exception
    {
    	this.setupFull();

    	assertTrue(this.groupIssuer.getGrpKey() != null,
    		   "Unexpected issuer's group key.");
    	assertTrue(this.groupIssuer.getMgrKey() != null,
    		   "Unexpected issuer's manager keys.");
    	assertTrue(this.groupIssuer.getIssKey() != null,
    		   "Unexpected issuer's issuer key.");
    	assertTrue(this.groupIssuer.getCnvKey() == null,
    		   "Unexpected issuer's converter key."); 	

    	assertTrue(this.groupConverter.getGrpKey() != null,
    		   "Unexpected converter's group key.");
    	assertTrue(this.groupConverter.getMgrKey() != null,
    		   "Unexpected converter's manager keys.");
    	assertTrue(this.groupConverter.getIssKey() == null,
    		   "Unexpected converter's issuer key.");
    	assertTrue(this.groupConverter.getCnvKey() != null,
    		   "Unexpected converter's converter keys."); 	

    	assertTrue(this.groupUser.getGrpKey() != null,
    		   "Unexpected user's group key.");
    	assertTrue(this.groupUser.getMgrKey() != null,
    		   "Unexpected user's manager keys.");
    	assertTrue(this.groupUser.getIssKey() == null,
    		   "Unexpected user's issuer key.");
    	assertTrue(this.groupUser.getCnvKey() == null,
    		   "Unexpected user's converter keys."); 	
	
    }

    @Test
    public void joinSeq()
    	throws Exception
    {
    	this.groupIssuer.setup();
    	int seq = this.groupIssuer.getJoinSeq();
    	assertTrue(seq == 3, "Unexpected join sequence steps.");
    }

    @Test
    public void joinStart()
    	throws Exception
    {
    	this.setupFull();
    	int start = this.groupIssuer.getJoinStart();
    	assertTrue(start == 0, "Unexpected join start.");
    }

    @Test void addsAMember()
    	throws Exception {
    	this.setupFull();
    	MemKey memkey = this.addMember();
    	assertTrue(memkey.getObject() != 0, "Failed to join member.");
    }

    @Test void signBytesAndVerifyCorrectly()
    	throws Exception {
    	this.setupFull();
    	MemKey memkey = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!".getBytes(), memkey);
    	boolean b = this.groupUser.verify(sig, "Hello, World!".getBytes());
    	assertTrue(b, "Signature should verify correctly.");
    }

    @Test void signBytesAndVerifyFails()
    	throws Exception {
    	this.setupFull();
    	MemKey memkey = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!".getBytes(), memkey);
    	boolean b = this.groupUser.verify(sig, "Hello, Worlds!".getBytes());
    	assertFalse(b, "Signature should not verify correctly.");
    }

    @Test void signStringAndVerifyCorrectly()
    	throws Exception {
    	this.setupFull();
    	MemKey memkey = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!", memkey);
    	boolean b = this.groupUser.verify(sig, "Hello, World!");
    	assertTrue(b, "Signature should verify correctly.");
    }

    @Test void signStringAndVerifyFails()
    	throws Exception {
    	this.setupFull();
    	MemKey memkey = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!", memkey);
    	boolean b = this.groupUser.verify(sig, "Hello, Worlds!");
    	assertFalse(b, "Signature should not verify correctly.");
    }

    @Test void blindConvertUnblindCorrectlySameMember()
    	throws Exception {

    	this.setupFull();

    	/* Add member */
    	MemKey memkey = this.addMember();

    	/* Create sample signatures */
    	Signature sig1 = this.groupUser.sign("Hello, World1!", memkey);
    	boolean b = this.groupUser.verify(sig1, "Hello, World1!");
    	assertTrue(b, "Signature should verify correctly.");
    	Signature sig2 = this.groupUser.sign("Hello, World2!", memkey);
    	b = this.groupUser.verify(sig2, "Hello, World2!");
    	assertTrue(b, "Signature should verify correctly.");

    	/* Create blinding key */
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());

    	/* Blind the signatures */
    	BlindSignature bSig1 = this.groupUser.blind(bldkey, sig1, "Hello, World1!");
    	BlindSignature bSig2 = this.groupUser.blind(bldkey, sig2, "Hello, World2!");
	
    	/* Convert the blinded signatures */

    	/* The converter will only need the public part of the blinding key: 
    	   simulate it */
    	String str = bldkey.exportPub();
    	assertTrue(str != null, "Unexpected public blinding key.");
		   
    	BldKey bldpub = new BldKey(this.groupUser.getCode(), str);
	
    	BlindSignature bSigsArray[] = new BlindSignature[2];
    	bSigsArray[0] = bSig1; bSigsArray[1] = bSig2;
	
    	BlindSignature cSigsArray[] = this.groupConverter.convert(bSigsArray, bldpub);
	
    	/* Unblind the signatures */
    	Identity id1 = this.groupUser.unblind(cSigsArray[0], bldkey);
    	Identity id2 = this.groupUser.unblind(cSigsArray[1], bldkey);

    	/* The nyms must be different */
    	b = id1.equals(id2);
    	assertTrue(b, "Identities should be the same.");
	
    }

    @Test void blindConvertUnblindCorrectlyDifferentMembers()
    	throws Exception {

    	this.setupFull();

    	/* Add members */
    	MemKey memkey1 = this.addMember();
    	MemKey memkey2 = this.addMember();

    	/* Create sample signatures */
    	Signature sig1 = this.groupUser.sign("Hello, World1!", memkey1);
    	boolean b = this.groupUser.verify(sig1, "Hello, World1!");
    	assertTrue(b, "Signature should verify correctly.");
    	Signature sig2 = this.groupUser.sign("Hello, World2!", memkey2);
    	b = this.groupUser.verify(sig2, "Hello, World2!");
    	assertTrue(b, "Signature should verify correctly.");

    	/* Create blinding key */
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());

    	/* Blind the signatures */
    	BlindSignature bSig1 = this.groupUser.blind(bldkey, sig1, "Hello, World1!");
    	BlindSignature bSig2 = this.groupUser.blind(bldkey, sig2, "Hello, World2!");
	
    	/* Convert the blinded signatures */
	
    	/* The converter will only need the public part of the blinding key: 
    	   simulate it */
    	BldKey bldpub = new BldKey(this.groupUser.getCode(), bldkey.exportPub());
	
    	BlindSignature bSigsArray[] = new BlindSignature[2];
    	bSigsArray[0] = bSig1; bSigsArray[1] = bSig2;
	
    	BlindSignature cSigsArray[] = this.groupConverter.convert(bSigsArray, bldpub);
	
    	/* Unblind the signatures */
    	Identity id1 = this.groupUser.unblind(cSigsArray[0], bldkey);
    	Identity id2 = this.groupUser.unblind(cSigsArray[1], bldkey);

    	/* The nyms must be different */
    	b = id1.equals(id2);
    	assertFalse(b, "Identities should be different.");
	
    }

    @Test
    public void exportImportGrpKey()
    	throws Exception
    {
    	this.setupFull();
    	String sgrp = this.groupUser.getGrpKey().export();
    	GrpKey gpk = new GrpKey(this.groupUser.getCode(), sgrp);
    	assertTrue(gpk.getObject() != 0, "Unexpected imported group key.");
    }

    @Test
    public void exportImportIssKey()
    	throws Exception
    {
    	this.setupFull();
    	String smgr = this.groupIssuer.getIssKey().export();
    	MgrKey gsk = new MgrKey(this.groupIssuer.getCode(), smgr);
    	assertTrue(gsk.getObject() != 0, "Unexpected imported issuer key.");
    }

    @Test
    public void exportImportCnvKey()
    	throws Exception
    {
    	this.setupFull();
    	String smgr = this.groupConverter.getCnvKey().export();
    	MgrKey gsk = new MgrKey(this.groupConverter.getCode(), smgr);
    	assertTrue(gsk.getObject() != 0, "Unexpected imported converter key.");
    }    

    @Test
    public void exportImportMemKey()
    	throws Exception
    {
    	this.setupFull();
    	MemKey mem = this.addMember();
    	String smem = mem.export();
    	MemKey mem2 = new MemKey(this.groupUser.getCode(), smem);
    	assertTrue(mem.getObject() != 0, "Unexpected imported member key.");
    }

    @Test
    public void exportImportBldKey()
    	throws Exception
    {
    	this.setupFull();
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());
    	String sbld = bldkey.export();
    	BldKey bldkey2 = new BldKey(this.groupUser.getCode(), sbld);
    	assertTrue(bldkey2.getObject() != 0, "Unexpected imported blinding key.");
    }

    @Test
    public void exportImportPubBldKey()
    	throws Exception
    {
    	this.setupFull();
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());	
    	String sbld = bldkey.exportPub();
    	BldKey bldkey2 = new BldKey(this.groupUser.getCode(), sbld);
    	assertTrue(bldkey2.getObject() != 0,
    		   "Unexpected imported public blinding key.");
    }       

    @Test
    public void exportImportSignature()
    	throws Exception
    {
    	this.setupFull();
    	MemKey mem = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!", mem);
    	String ssig = sig.export();
    	Signature sig2 = new Signature(this.groupUser.getCode(), ssig);
    	boolean b = this.groupUser.verify(sig2, "Hello, World!");
    	assertTrue(b, "Imported signature should verify correctly.");
    }

    @Test
    public void exportImportBlindSignature()
    	throws Exception
    {
    	this.setupFull();
    	MemKey mem = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!", mem);
    	boolean b = this.groupUser.verify(sig, "Hello, World!");
    	assertTrue(b, "Imported signature should verify correctly.");
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());
    	BlindSignature bSig = this.groupUser.blind(bldkey, sig, "Hello, World!");
    	String str = bSig.export();
    	BlindSignature bSig2 = new BlindSignature(this.groupUser.getCode(), str);
    	assertTrue(bSig2.getObject() != 0, "Unexpected blind signature.");	
    }

    @Test
    public void exportImportConvertedSignature()
    	throws Exception
    {
    	this.setupFull();
    	MemKey mem = this.addMember();
    	Signature sig = this.groupUser.sign("Hello, World!", mem);
    	boolean b = this.groupUser.verify(sig, "Hello, World!");
    	assertTrue(b, "Imported signature should verify correctly.");
    	BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, this.groupUser.getGrpKey());
    	BlindSignature bSig = this.groupUser.blind(bldkey, sig, "Hello, World!");
    	BlindSignature bSigsArray[] = new BlindSignature[1];
    	bSigsArray[0] = bSig;
    	BldKey bldpub = new BldKey(this.groupUser.getCode(), bldkey.exportPub());
    	BlindSignature cSigsArray[] = this.groupConverter.convert(bSigsArray, bldpub);
    	String str = cSigsArray[0].export();
    	BlindSignature cSig = new BlindSignature(this.groupUser.getCode(), str);
    	assertTrue(cSig.getObject() != 0, "Unexpected converted signature.");
	
    }    
    
}
