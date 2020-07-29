package com.ibm.jgroupsig;

import java.net.URL;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;

public class Util {

    public Util () {};
    
    public static void LoadNativeLib(String libName) {

	try {
	    URL url = Util.class.getResource("/" + libName);
	    File tmpDir = Files.createTempDirectory(libName).toFile();
	    tmpDir.deleteOnExit();
	    File nativeLibTmpFile = new File(tmpDir, libName);
	    nativeLibTmpFile.deleteOnExit();
	    InputStream in = url.openStream();
	    Files.copy(in, nativeLibTmpFile.toPath());
	    System.load(nativeLibTmpFile.getAbsolutePath());	    
	} catch (IOException ioe) {
	    ioe.printStackTrace();
	}

    }

}
