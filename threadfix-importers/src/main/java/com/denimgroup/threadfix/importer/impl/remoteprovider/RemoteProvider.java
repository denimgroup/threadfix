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
package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;

public abstract class RemoteProvider extends AbstractChannelImporter {
	
	public RemoteProvider(ScannerType scannerType) {
		super(scannerType);
	}

	protected final SanitizedLogger LOG = new SanitizedLogger(this.getClass());
	
	protected RemoteProviderType remoteProviderType;
	
	public abstract List<Scan> getScans(RemoteProviderApplication remoteProviderApplication);
	
	public abstract List<RemoteProviderApplication> fetchApplications();
	
	public void setRemoteProviderType(RemoteProviderType remoteProviderType) {
		this.remoteProviderType = remoteProviderType;
	}
	
	// These are to make AbstractChannelImporter happy while still getting all of the utility methods from it.
	@Override
	public Scan parseInput() {
		LOG.warn("parseInput() called in a Remote Provider. This should never happen.");
		return null;
	}

	@Override
	public ScanCheckResultBean checkFile() {
		LOG.warn("checkFile() called in a Remote Provider. This should never happen.");
		return null;
	}
	
	protected void parse(InputStream inputStream, DefaultHandler handler) {
		if (inputStream == null) {
			LOG.error("Null inputStream argument. Can't continue.");
			return;
		} else if (handler == null) {
			LOG.error("Null handler argument. Can't continue.");
			return;
		}
		
		try {
			XMLReader xmlReader = XMLReaderFactory.createXMLReader();
		
			xmlReader.setContentHandler(handler);
			xmlReader.setErrorHandler(handler);
			
			Reader fileReader = new InputStreamReader(inputStream,"UTF-8");
			
			InputSource source = new InputSource(fileReader);
			source.setEncoding("UTF-8");
			xmlReader.parse(source);
		} catch (SAXException | IOException e) {
			LOG.warn("Exception encountered while attempting to parse XML.", e);
			e.printStackTrace();
		} finally {
			try {
                inputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
