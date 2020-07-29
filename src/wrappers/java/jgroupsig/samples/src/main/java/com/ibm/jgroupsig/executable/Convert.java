package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.*;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;

public class Convert {

    /* Credit to https://stackoverflow.com/a/13006907 */
    private static String byteArrayToHex(byte[] a) {
	StringBuilder sb = new StringBuilder(a.length * 2);
	for(byte b: a)
	    sb.append(String.format("%02x", b));
	return sb.toString();
    }    

    private static MemKey addMember(GL19 issuer)
	throws IllegalArgumentException,
	       Exception
    {
	
	MemKey memkey = new MemKey(3);
	
	long mout1 = issuer.joinMgr(0, 0);
	if (mout1 == 0) {
	    return null;
	}
	
	long mout2 = issuer.joinMem(memkey, 1, mout1);
	if (mout2 == 0) {
	    return null;
	}
	
	long mout3 = issuer.joinMgr(2, mout2);
	if (mout3 == 0) {
	    return null;
	}
	
	issuer.joinMem(memkey, 3, mout3);

	return memkey;
	
    }
    
    public static void main(String args[]) {

	try {

	    GL19 issuer = new GL19();
	    GL19 converter = new GL19();
	    GL19 user = new GL19();

	    /* Setup all the entities -- this can be done remotely in 
	       a real setting by serializing and sharing the input parameters */
	    issuer.setup();
	    converter.setup(issuer.getGrpKey());
	    issuer.setup(converter.getGrpKey());
	    user.setGrpKey(issuer.getGrpKey());

	    /* Simulate adding one member */
	    MemKey memkey = addMember(issuer);

	    /* Create sample signatures */
	    Signature sig1 = user.sign("Hello, World1!", memkey);
	    boolean b = user.verify(sig1, "Hello, World1!");
	    Signature sig2 = user.sign("Hello, World2!", memkey);
	    b = user.verify(sig2, "Hello, World2!");

	    /* Generate a random blinding key */
	    BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, user.getGrpKey());

	    /* Blind the signatures */
	    BlindSignature bSig1 = user.blind(bldkey, sig1, "Hello, World1!");
	    BlindSignature bSig2 = user.blind(bldkey, sig2, "Hello, World2!");

	    /* Convert */
	    BlindSignature bSigsArray[] = new BlindSignature[2];
	    bSigsArray[0] = bSig1; bSigsArray[1] = bSig2;
	    
	    BlindSignature cSigsArray[] = converter.convert(bSigsArray, bldkey);

	    /* Unblind the signatures */
	    Identity id1 = user.unblind(cSigsArray[0], bldkey);
	    Identity id2 = user.unblind(cSigsArray[1], bldkey);

	    /* Print result */
	    System.out.println("Sig 1: \n\tID: "+id1.toStr()+
			       "\n\tMessage hash: 0x"+byteArrayToHex(id1.getMsg()).substring(0,32)+"...");
	    System.out.println("Sig 2: \n\tID: "+id2.toStr()+
			       "\n\tMessage hash: 0x"+byteArrayToHex(id2.getMsg()).substring(0,32)+"...");
	    
	    
	} catch (UnsupportedEncodingException uee) {
	    System.out.println(uee);
	} catch (IllegalArgumentException iae) {
	    System.out.println(iae);
	} catch (Exception e) {
	    System.out.println(e);
	} 
    }

}
