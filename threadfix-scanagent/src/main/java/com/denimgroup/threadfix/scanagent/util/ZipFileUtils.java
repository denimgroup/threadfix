////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.scanagent.util;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ZipFileUtils {
	/**
	 * Prevent instantiation
	 */
	private ZipFileUtils() { }
	
	/**
	 * 	This method was copied/adapted from:
	 * 	http://www.java2s.com/Tutorial/Java/0180__File/unzipFileIntoDirectory.htm
	 * 
	 * TODO - This is kinda gross. Clean it up.
	 * 
	 * @param zipFilename Location of the ZIP file to unpack
	 * @param targetPath Base path where the ZIP file shoudl be unpacked
	 */
	@SuppressWarnings({ "unchecked", "resource" })
	public static void unzipFile(@NotNull String zipFilename, @NotNull String targetPath)
	throws java.io.IOException {
		
		ZipFile zipFile = new ZipFile(zipFilename);
		File jiniHomeParentDir = new File(targetPath);
		
		Enumeration<ZipEntry> files = (Enumeration<ZipEntry>) zipFile.entries();
		
	    while (files.hasMoreElements()) {
            try {
                ZipEntry entry  = files.nextElement();
                InputStream eis = zipFile.getInputStream(entry);
                byte[] buffer = new byte[1024];
                int bytesRead;

                File file = new File(jiniHomeParentDir.getAbsolutePath() + File.separator + entry.getName());

                if (entry.isDirectory()) {
                    file.mkdirs();
                    continue;
                } else {
                    file.getParentFile().mkdirs();
                    file.createNewFile();
                }

                try (FileOutputStream fos = new FileOutputStream(file)) {
                    while ((bytesRead = eis.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
	    }
	}
}
