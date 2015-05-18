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
package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.annotations.StartingTagSet;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.enumMap;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 *
 * @author mcollins
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.NTO_SPIDER_DB_NAME,
        startingXMLTagSets = {
                @StartingTagSet({ "VULNS", "VULNLIST" }),
                @StartingTagSet({ "VulnSummary" })
        }
)
public class NTOSpiderChannelImporter extends AbstractChannelImporter {
	private static Map<String, FindingKey> tagMap = map();
	static {
		tagMap.put("vulntype",      FindingKey.VULN_CODE);
		tagMap.put("attackscore",   FindingKey.SEVERITY_CODE);
		tagMap.put("parametername", FindingKey.PARAMETER);
		tagMap.put("normalizedurl", FindingKey.PATH);
	}

	private static final String VULN_TAG = "vuln", SCAN_DATE = "scandate",
			DATE_PATTERN = "yyyy-MM-dd kk:mm:ss", N_A = "n/a", VULN_LIST = "vulnlist",
			VULN_SUMMARY = "VulnSummary";

	public NTOSpiderChannelImporter() {
		super(ScannerType.NTO_SPIDER);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new NTOSaxParser());
	}

	public class NTOSaxParser extends HandlerWithBuilder {
		
		private boolean getDate   = false;
		private boolean inFinding = false;
		
		private FindingKey itemKey = null;
	
		private Map<FindingKey, String> findingMap = null;
		
	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);
	    		saxFindingList.add(finding);
    		}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if (date == null && SCAN_DATE.equalsIgnoreCase(qName)) {
	    		getDate = true;
	    	} else if (VULN_TAG.equalsIgnoreCase(qName)) {
	    		findingMap = enumMap(FindingKey.class);
	    		inFinding = true;
	    	} else if (inFinding && tagMap.containsKey(qName.toLowerCase())) {
	    		itemKey = tagMap.get(qName.toLowerCase());
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName)
	    {
	    	if (VULN_TAG.equalsIgnoreCase(qName)) {
	    		
	    		if (findingMap.get(FindingKey.PARAMETER) != null && 
	    				findingMap.get(FindingKey.PARAMETER).equals(N_A)) {
	    			findingMap.remove(FindingKey.PARAMETER);
	    		}
	    		
	    		Finding finding = constructFinding(findingMap);
	    		
	    		add(finding);
	    		findingMap = null;
	    		inFinding = false;
	    	} else if (inFinding && itemKey != null) {
	    		String currentItem = getBuilderText();
	    		if (currentItem != null && findingMap.get(itemKey) == null) {
	    			findingMap.put(itemKey, currentItem);
	    		}
	    		itemKey = null;
	    	} else if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = DateUtils.getCalendarFromString(DATE_PATTERN, tempDateString);
	    		}
	    		getDate = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || itemKey != null) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new NTOSaxValidator());
	}
	
	public class NTOSaxValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    @Override
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (VULN_LIST.equalsIgnoreCase(qName) || VULN_SUMMARY.equalsIgnoreCase(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if (testDate == null && SCAN_DATE.equalsIgnoreCase(qName)) {
	    		getDate = true;
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String name, String qName) throws SAXException { 	
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			testDate = DateUtils.getCalendarFromString(DATE_PATTERN, tempDateString);
	    		}
	    		
	    		hasDate = testDate != null;
	    		getDate = false;
	    	}
	    	
	    	if (VULN_TAG.equalsIgnoreCase(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
}
