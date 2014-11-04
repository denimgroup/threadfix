////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.exception.RestInvalidScanFormatException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import java.io.*;

/**
 * This class is included because it is sometimes useful for these methods to appear
 * outside of the AbstractChannelImporter. For example, when trying to determine the type
 * of scanner that produced an uploaded file, the readSAXInput method can be a helpful tool.
 * 
 * @author mcollins
 *
 */
public final class ScanUtils {
	
	private static final SanitizedLogger STATIC_LOGGER = new SanitizedLogger(ScanUtils.class);

	private ScanUtils(){}
	
	/**
	 * This method checks through the XML with a blank parser to determine
	 * whether SAX parsing will fail due to an exception.
	 */
	public static boolean isBadXml(InputStream inputStream) {
		try {
			readSAXInput(new DefaultHandler(), inputStream);
            return false;
		} catch (SAXException | IOException e) {
            STATIC_LOGGER.warn("Trying to read XML returned the error " + e.getMessage(), e);
        } catch (RestIOException e) {
            STATIC_LOGGER.warn("Invalid XML. Rethrowing as RestInvalidFormatException");
            throw new RestInvalidScanFormatException(e, "Invalid scan format.");
		} finally {
			closeInputStream(inputStream);
		}

		return true;
	}
	
	/**
	 * This method with one argument sets up the SAXParser and inputStream correctly
	 * and executes the parsing. With two it adds a completion code and exception handling.
	 */
	public static void readSAXInput(DefaultHandler handler, String completionCode, InputStream stream) {
		try {
			readSAXInput(handler, stream);
		} catch (IOException e) {
            STATIC_LOGGER.error("Encountered IOException while trying to read the SAX input.");
            throw new RestIOException(e, "Encountered IOException while trying to read data. Can't continue.");
		} catch (SAXException e) {
			if (!e.getMessage().equals(completionCode)) {
                STATIC_LOGGER.error("Encountered SAXException while trying to read the SAX input.");
                throw new RestIOException(e, "Encountered SAXException while trying to read data. Can't continue.");
            }
		} finally {
			closeInputStream(stream);
		}
	}
	
	public static void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				STATIC_LOGGER.warn("Closing an input stream failed.", ex);
			}
		}
	}
	
	private static void readSAXInput(DefaultHandler handler, InputStream stream) throws SAXException, IOException {
		XMLReader xmlReader = XMLReaderFactory.createXMLReader();
		xmlReader.setContentHandler(handler);
		xmlReader.setErrorHandler(handler);
				
		// Wrapping the inputStream in a BufferedInputStream allows us to mark and reset it
		BufferedInputStream newStream = new BufferedInputStream(stream);
		
		// UTF-8 contains 3 characters at the start of a file, which is a problem.
		// The SAX parser sees them as characters in the prolog and throws an exception.
		// This code removes them if they are present.
		newStream.mark(4);
		
		if (newStream.read() == 239) {
			newStream.read(); newStream.read();
		} else
			newStream.reset();
		
		Reader fileReader = new InputStreamReader(newStream,"UTF-8");
		InputSource source = new InputSource(fileReader);
		source.setEncoding("UTF-8");
		xmlReader.parse(source);
	}
	
	public static boolean isZip(String fileName) {
		try (RandomAccessFile file = new RandomAccessFile(new File(fileName), "r")) {
			// these are the magic bytes for a zip file
	        return file.readInt() == 0x504B0304;
		} catch (FileNotFoundException e) {
			STATIC_LOGGER.warn("The file was not found. Check the usage of this method.", e);
		} catch (IOException e) {
			STATIC_LOGGER.warn("Encountered IOException while trying to figure out whether the file is a zip file.", e);
		}
		
		return false;
	}
}
