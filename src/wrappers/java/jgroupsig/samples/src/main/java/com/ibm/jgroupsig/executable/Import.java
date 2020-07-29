package com.ibm.jgroupsig.executable;

import com.ibm.jgroupsig.*;

import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;

public class Import {

    /* Credit to https://stackoverflow.com/a/13006907 */
    private static String byteArrayToHex(byte[] a) {
	StringBuilder sb = new StringBuilder(a.length * 2);
	for(byte b: a)
	    sb.append(String.format("%02x", b));
	return sb.toString();
    }    

    /* Credit to https://stackoverflow.com/a/4716623 */
    private static String file2String(String fileName) {
	try(BufferedReader br = new BufferedReader(new FileReader(fileName))) {
	    StringBuilder sb = new StringBuilder();
	    String line = br.readLine();

	    while (line != null) {
		sb.append(line);
		sb.append(System.lineSeparator());
		line = br.readLine();
	    }
	    String everything = sb.toString();
	    return everything;
	} catch(FileNotFoundException fnfe) {
	    System.out.println(fnfe);
	} catch(IOException ioe) {
	    System.out.println(ioe);
	}       
	return null;
    }

    private static MemKey addMember(GS group)
	throws IllegalArgumentException,
	       Exception
    {

	MemKey memkey = new MemKey(3);
	
	long mout1 = group.joinMgr(0, 0);
	if (mout1 == -1) {
	    System.out.println("Error in joinMgr");
	    return null;
	}
	
	long mout2 = group.joinMem(memkey, 1, mout1);
	if (mout2 == -1) {
	    System.out.println("Error in joinMem");
	    return null;
	}
	
	long mout3 = group.joinMgr(2, mout2);
	if (mout3 == -1) {
	    System.out.println("Error in joinMgr 2");
	    return null;
	}

	long mout4 = group.joinMem(memkey, 3, mout3);
	if (mout4 == -1) {
	    System.out.println("Error in joinMem 2");
	    return null;
	}

	return memkey;
	
    }    
    
    public static void main(String args[]) {

	try {

	    GL19 issuer = new GL19();
	    GL19 converter = new GL19();
	    GL19 user = new GL19();

	    /* Read isskey from file */
	    String issstr = file2String("iss.key");
	    MgrKey isskey = new MgrKey(3, issstr);

	    /* Read cnvkey from file */
	    String cnvstr = file2String("cnv.key");
	    MgrKey cnvkey = new MgrKey(3, cnvstr);	    

	    /* Read grpkey from file */
	    String grpstr = file2String("grp.key");
	    GrpKey grpkey = new GrpKey(3, grpstr);

	    issuer.setGrpKey(grpkey);
	    issuer.setIssKey(isskey);
	    converter.setGrpKey(grpkey);
	    converter.setCnvKey(cnvkey);
	    user.setGrpKey(grpkey);
	    
	    /* Read memkey from file */
	    String memstr1 = file2String("mem1.key");
	    MemKey memkey1 = new MemKey(GS.GL19_CODE, memstr1);

	    String memstr2 = file2String("mem2.key");
	    MemKey memkey2 = new MemKey(GS.GL19_CODE, memstr2);	    

	    /* Read bldkey from file */
	    String bldstr = file2String("bld.key");
	    BldKey bldkey = new BldKey(GS.GL19_CODE, bldstr);

	    /* Read signature from file */
	    String sigstr1 = file2String("msg1.sig");
	    Signature sig1 = new Signature(3, sigstr1);
	    String sigstr2 = file2String("msg2.sig");
	    Signature sig2 = new Signature(3, sigstr2); 	    

	    /* Verify the signatures */
	    boolean b = user.verify(sig1, "Hello, World!");
	    if (b == true) System.out.println("VALID signature.");
	    else System.out.println("WRONG signature.");

	    b = user.verify(sig2, "Hello, World2!");
	    if (b == true) System.out.println("VALID signature.");
	    else System.out.println("WRONG signature.");

	    /* Import blinded signatures */
	    String sbsig1 = file2String("msg1.bsig");
	    BlindSignature bSig1 = new BlindSignature(3, sbsig1);

	    String sbsig2 = file2String("msg2.bsig");
	    BlindSignature bSig2 = new BlindSignature(3, sbsig2);   

	    /* Convert */
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
	    
	    
	} catch (UnsupportedEncodingException uee) {
	    System.out.println(uee);
	} catch (IllegalArgumentException iae) {
	    System.out.println(iae);
	} catch (Exception e) {
	    System.out.println(e);
	} 
    }

}
