////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Calendar;
import java.util.List;

import static com.denimgroup.threadfix.CloseableUtils.closeQuietly;
import static com.denimgroup.threadfix.CollectionUtils.list;

public abstract class AbstractRemoteProvider extends AbstractChannelImporter {

	public AbstractRemoteProvider(ScannerType scannerType) {
		super(scannerType);
	}

	public AbstractRemoteProvider(String scannerType) {
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
        assert false;
		return null;
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		LOG.warn("checkFile() called in a Remote Provider. This should never happen.");
        assert false;
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
		} catch (SAXException e) {
			LOG.warn("Exception encountered while attempting to parse XML.", e);
			e.printStackTrace();
		} catch (IOException e) {
			LOG.warn("Exception encountered while attempting to parse XML.", e);
			e.printStackTrace();
		} finally {
			closeQuietly(inputStream);
        }
    }

    protected String getAuthenticationFieldValue(String key) {

        assert remoteProviderType != null : "Remote Provider type was null, can't continue.";

        for (RemoteProviderAuthenticationField field : remoteProviderType.getAuthenticationFields()) {
            if (key.equals(field.getName())) {
                return field.getValue();
            }
        }

        assert false : "Didn't find a value for " + key;
        return null;
    }

	/**
	 * This method checks if there are 2 scans with consecutive imported dates and same finding list. If any, remove the earlier one.
	 * @param scans
	 * @return
	 */
	protected List<Scan> filterScans(List<Scan> scans) {
		List<Scan> resultList = list();

		for (Scan s: scans) {
			resultList.add(s);
		}

		for (int i = 0; i < scans.size() - 1; i++) {
			Scan scan1 = scans.get(i);
			Calendar date1 = scan1.getImportTime();
			Scan scan2 = scans.get(i+1);
			Calendar date2 = scan2.getImportTime();

			// Checking if they have consecutive imported dates
			if ((date2.getTimeInMillis()-date1.getTimeInMillis())/(24*60*60*1000)==1) {
				if (scan1.getFindings().size() == scan2.getFindings().size()) {
					boolean isDuplicatedScan = true;
					List<Finding> findingList1 = scan1.getFindings();
					List<Finding> findingList2 = scan2.getFindings();

					for (int j=0; j<findingList1.size(); j++) {
						if (!findingList1.get(j).getNativeId().equals(findingList2.get(j).getNativeId())) {
							isDuplicatedScan = false;
							break;
						}
					}

					if (isDuplicatedScan) resultList.remove(scan1);
				}
			}
		}

		return resultList;
	}
}
