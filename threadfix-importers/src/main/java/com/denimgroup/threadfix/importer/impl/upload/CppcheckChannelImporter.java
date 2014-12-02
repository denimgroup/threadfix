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

package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.CPPCHECK_DB_NAME;

/**
 * 
 * @author sgerick
 */
@ScanImporter(
        scannerName = CPPCHECK_DB_NAME,
        startingXMLTags = {"results", "cppcheck", "errors", "error"}
)
public class CppcheckChannelImporter extends AbstractChannelImporter {

	public CppcheckChannelImporter() {
		super(ScannerType.CPPCHECK);
	}


	@Override
	public Scan parseInput() {
		return parseSAXInput(new CppcheckSAXParser());
	}
	
	public class CppcheckSAXParser extends HandlerWithBuilder {
		Map<FindingKey, String> findingMap;
		List<DataFlowElement> dataFlowElements;
        private boolean inFinding = false;
		private String errorId;
		private String errorSeverity;
		private String errorMsg;
		private String errorVerbose;
		private String locationFile;
		private String locationLine;
		private String findingPath;

        private StringBuffer currentRawFinding	  = new StringBuffer();

	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(true);
	    		saxFindingList.add(finding);
    		}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
		    if ("error".equals(qName)) {
			    findingMap = new HashMap<>();
			    dataFlowElements = new ArrayList<>();

			    inFinding = true;
			    errorId = atts.getValue("id");
			    errorSeverity = atts.getValue("severity");
			    errorMsg = atts.getValue("msg");
			    errorVerbose = atts.getValue("verbose");
			    if (errorMsg.equals(errorVerbose))          // no reason for duplicating verbose with message.
				    errorVerbose = null;
		    }
		    if ("location".equals(qName)) {
			    locationFile = atts.getValue("file");
			    locationLine = atts.getValue("line");
			    if (findingPath == null)
				    findingPath = locationFile;
		    }
            if (inFinding){
                currentRawFinding.append(makeTag(name, qName , atts));
            }
	    }

	    public void endElement (String uri, String name, String qName)
	    {
            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }

		    if ("location".equals(qName)) {
			    DataFlowElement element = new DataFlowElement();
				element.setSourceFileName(locationFile);
			    element.setLineNumber(Integer.parseInt(locationLine));
			    dataFlowElements.add(element);
			    locationFile = null;
			    locationLine = null;
		    }
	    	if ("error".equals(qName)) {
				findingMap.put(FindingKey.VULN_CODE, errorId);
			    findingMap.put(FindingKey.SEVERITY_CODE, errorSeverity);
			    findingMap.put(FindingKey.DETAIL, errorMsg);
			    findingMap.put(FindingKey.RECOMMENDATION, errorVerbose);
			    findingMap.put(FindingKey.PATH, findingPath);
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
			    Finding finding = constructFinding(findingMap);

			    if (finding == null) {
				    throw new IllegalStateException("XML was invalid or we didn't parse out enough information");
			    }
			    finding.setDataFlowElements(dataFlowElements);
	    		add(finding);
	    		
			    errorId = null;
			    errorSeverity = null;
			    errorMsg = null;
			    errorVerbose = null;
			    findingPath = null;

                inFinding = false;
                currentRawFinding.setLength(0);
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
            if (inFinding)
                currentRawFinding.append(ch,start,length);
	    }

	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new CppcheckSAXValidator());
	}
	
	public class CppcheckSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean foundResults = false;
		private boolean foundCppCheck = false;
		private String xmlVersion;

	    private void setTestStatus() {
		    if (!foundCppCheck || !foundResults || !"2".equals(xmlVersion))
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;

	    	if (ScanImportStatus.SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public final void endDocument() {
	    	setTestStatus();
	    }

	    public final void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
		    if ("results".equals(qName)) {
			    xmlVersion = atts.getValue("version");
			    foundResults = true;
		    }
		    if ("cppcheck".equals(qName))
			    foundCppCheck = true;
		    if ("error".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
		    }
	    }
	    
	}
}
