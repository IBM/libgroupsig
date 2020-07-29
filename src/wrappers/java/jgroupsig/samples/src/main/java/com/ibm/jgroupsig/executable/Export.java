package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.*;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.FileReader;
import java.io.BufferedReader;

public class Export {

    /* Credit to https://stackoverflow.com/a/13006907 */
    private static String byteArrayToHex(byte[] a) {
	StringBuilder sb = new StringBuilder(a.length * 2);
	for(byte b: a)
	    sb.append(String.format("%02x", b));
	return sb.toString();
    }
    
    /* Credit to https://stackoverflow.com/a/4716623 */
    private static void string2File(String str, String fileName) {

	try (PrintWriter out = new PrintWriter(fileName)) {
	    out.println(str);
	} catch (FileNotFoundException fnfe) {
	    System.out.println(fnfe);
	}

    }

    private static MemKey addMember(GS group)
	throws IllegalArgumentException,
	       Exception
    {

	MemKey memkey = new MemKey(3);

	long mout1 = group.joinMgr(0, 0);
	if (mout1 == 0) {
	    System.out.println("Error in joinMgr");
	    return null;
	}

	long mout2 = group.joinMem(memkey, 1, mout1);
	if (mout2 == 0) {
	    System.out.println("Error in joinMem");
	    return null;
	}

	long mout3 = group.joinMgr(2, mout2);
	if (mout3 == 0) {
	    System.out.println("Error in joinMgr 2");
	    return null;
	}

	group.joinMem(memkey, 3, mout3);

	return memkey;
	
    }
    
    public static void main(String args[]) {

	try {
	    
	    GL19 issuer = new GL19();
	    GL19 converter = new GL19();
	    GL19 user = new GL19();

	    issuer.setup();
	    converter.setup(issuer.getGrpKey());
	    issuer.setup(converter.getGrpKey());
	    user.setGrpKey(issuer.getGrpKey());

	    /* Add members */
	    MemKey memkey1 = addMember(issuer);
	    MemKey memkey2 = addMember(issuer);

	    /* Create signatures */
	    Signature sig1 = user.sign("Hello, World!", memkey1);
	    Signature sig2 = user.sign("Hello, World2!", memkey1);

	    /* Verify signatures */

	    boolean b = user.verify(sig1, "Hello, World!");
	    if (b == true) System.out.println("VALID signature.");
	    else System.out.println("WRONG signature.");

	    b = user.verify(sig2, "Hello, World2!");
	    if (b == true) System.out.println("VALID signature.");
	    else System.out.println("WRONG signature.");

	    /* Get random blinding key */
	    BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, user.getGrpKey());

	    /* Blind signatures */	    
	    BlindSignature bSig1 = user.blind(bldkey, sig1, "Hello, World!");
	    BlindSignature bSig2 = user.blind(bldkey, sig2, "Hello, World2!");
	    
	    /* Convert signatures */
	    BlindSignature bSigsArray[] = new BlindSignature[2];
	    bSigsArray[0] = bSig1; bSigsArray[1] = bSig2;

	    BlindSignature cSigsArray[] = converter.convert(bSigsArray, bldkey);

	    /* Unblind */
	    Identity id1 = user.unblind(cSigsArray[0], bldkey);
	    Identity id2 = user.unblind(cSigsArray[1], bldkey);

	    /* Print result */
	    System.out.println("Sig 1: \n\tID: "+id1.toStr()+
			       "\tMessage hash: 0x"+byteArrayToHex(id1.getMsg()).substring(0,32)+"...");
	    System.out.println("Sig 2: \n\tID: "+id2.toStr()+
			       "\tMessage hash: 0x"+byteArrayToHex(id2.getMsg()).substring(0,32)+"...");


	    /* Export memkey */
	    String memstr = memkey1.export();
	    string2File(memstr, "mem1.key");

	    memstr = memkey2.export();
	    string2File(memstr, "mem2.key");

	    /* Export isskey */
	    MgrKey isskey = issuer.getIssKey();
	    String issstr = isskey.export();
	    string2File(issstr, "iss.key");

	    /* Export cnvkey */
	    MgrKey cnvkey = converter.getCnvKey();
	    String cnvstr = cnvkey.export();
	    string2File(cnvstr, "cnv.key");

	    /* Export grpkey */
	    GrpKey grpkey = user.getGrpKey();
	    String grpstr = grpkey.export();
	    string2File(grpstr, "grp.key");

	    /* Export bldkey */
	    String bldstr = bldkey.export();
	    string2File(bldstr, "bld.key");

	    /* Export signatures */
	    String sigstr = sig1.export();
	    string2File(sigstr, "msg1.sig");

	    sigstr = sig2.export();
	    string2File(sigstr, "msg2.sig");  

	    /* Export blind signatures */
	    String bsigstr = bSig1.export();
	    string2File(bsigstr, "msg1.bsig");

	    bsigstr = bSig2.export();
	    string2File(bsigstr, "msg2.bsig");  

	    /* Export converted signatures */
	    String csigstr = cSigsArray[0].export();
	    string2File(csigstr, "msg1.csig");

	    csigstr = cSigsArray[1].export();
	    string2File(csigstr, "msg2.csig");  
	    
	    
	} catch (UnsupportedEncodingException uee) {
	    uee.printStackTrace();
	} catch (IllegalArgumentException iae) {
	    iae.printStackTrace();
	} catch (Exception e) {
	    e.printStackTrace();
	} 
    }

}
