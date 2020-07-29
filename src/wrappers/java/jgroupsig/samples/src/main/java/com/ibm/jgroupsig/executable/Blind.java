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

public class Blind {

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

    /* Credit to https://stackoverflow.com/a/4716623 */
    private static void string2File(String str, String fileName) {

	try (PrintWriter out = new PrintWriter(fileName)) {
	    out.println(str);
	} catch (FileNotFoundException fnfe) {
	    System.out.println(fnfe);
	}

    }   

    public static void main(String args[]) {

	if (args.length != 3) {
	    System.out.println("Usage: java Blind <group key str> <signature str> <message str>");
	    return;
	}
	
	try {

	    GL19 user = new GL19();
   
	    /* Import grpkey from first command line argument */
	    String grpstr = file2String(args[0]);
	    GrpKey grpkey = new GrpKey(3, grpstr);
	    user.setGrpKey(grpkey);

	    /* Import signature from second command line argument */
	    String sigstr = file2String(args[1]);	    
	    Signature sig = new Signature(GS.GL19_CODE, sigstr);

	    /* Import message from third command line argument */
	    String msg = args[2];

	    /* Verify the signature */
	    boolean b = user.verify(sig, msg);
	    if (b == false) {
		System.out.println("WRONG signature.");
		return;
	    }

	    /* Get random blinding key */
	    BldKey bldkey = BldKey.getRandom(GS.GL19_CODE, user.getGrpKey());

	    /* Blinded signatures */	    
	    BlindSignature bSig = user.blind(bldkey, sig, msg);
	    
	    /* Export blinded signature and bldkey to strings */
	    String bldstr = bldkey.export();
	    String bsigstr = bSig.export();
	    
	    /* Print blinded signature and bldkey */
	    System.out.println("Blinding key: "+bldstr);
	    System.out.println("Blinded signature: "+bsigstr);
	    	    
	} catch (UnsupportedEncodingException uee) {
	    System.out.println(uee);
	} catch (IllegalArgumentException iae) {
	    System.out.println(iae);
	} catch (Exception e) {
	    System.out.println(e);
	}

	return;
	
    }

}
