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
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * 
 * @author mcollins
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.APPSCAN_SOURCE_DB_NAME,
        startingXMLTags = { "AssessmentRun", "AssessmentStats" }
)
public class AppScanSourceChannelImporter extends AbstractChannelImporter {

	private static final SanitizedLogger LOG = new SanitizedLogger(AppScanSourceChannelImporter.class);

	private static final Map<String, String> REGEX_MAP = map();
	static {
		REGEX_MAP.put("System.Data.Common.DbDataReader.get_Item", 
				"System\\.Data\\.Common\\.DbDataReader\\.get_Item " +
				"\\( \\(System\\.String\\)\"([^\"]+)\"");
		REGEX_MAP.put("System.Web.HttpRequest.get_Item", 
				"System\\.Web\\.HttpRequest\\.get_Item \\( \\(System.String\\)\"([^\"]+)\" \\)");
		REGEX_MAP.put("System.Web.UI.WebControls.TextBox.get_Text", 
				"([^ >\\.]+) . System.Web.UI.WebControls.TextBox.get_Text \\(\\)");
		REGEX_MAP.put("System.Web.UI.WebControls.HiddenField.get_Text", 
				"([^ >\\.]+) . System.Web.UI.WebControls.HiddenField.get_Value \\(\\)");
		REGEX_MAP.put("javax.servlet.http.HttpSession.getAttribute",
				"javax\\.servlet\\.http\\.HttpSession\\.getAttribute \\( \"([^\"]+)\" \\)");
		REGEX_MAP.put("java.sql.ResultSet.getString",
				"java\\.sql\\.ResultSet\\.getString \\( \"([^\"]+)\" \\)");
		REGEX_MAP.put("javax.servlet.ServletRequest.getParameter",
				"javax\\.servlet\\.ServletRequest\\.getParameter \\( \"([^\"]+)\" \\)");
	}

	public AppScanSourceChannelImporter() {
		super(ScannerType.APPSCAN_SOURCE);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new AppScanSourceSAXParser());
	}
	
	private Calendar getCalendarFromTimeInMillisString(String timeInMillis) {
		try {
			Long timeLong = Long.valueOf(timeInMillis);
			Calendar calendar = Calendar.getInstance();
			calendar.setTimeInMillis(timeLong);
			return calendar;
		} catch (NumberFormatException e) {
			log.warn("Invalid date timestamp in Appscan source file.", e);
			return null;
		}
	}

	public class AppScanSourceSAXParser extends DefaultHandler {
		
		private Map<String, String> stringValueMap = map();
		// String.id -> String.value
		private Map<String, String> fileMap = map();
		// File.id -> File.value
		private Map<String, Map<String,String>> siteMap = map();
		// Site.id -> ("fileId" -> File.id, "line" -> File.ln, "column" -> Site.col, "methodId" -> Site.method)
		private Map<String, Map<String, String>> findingDataMap = map();
		// FindingData.id -> ("vulnType" -> FindingData.vtype, "siteId" -> FindingData.site_id, "sev" -> FindingData.sev)
		private Map<String, Map<String, String>> taintMap = map();
		// Taint.id -> ("argName" -> Taint.arg_name, "siteId" -> Taint.site_id, "arg" -> Taint.arg)

		/*
		 * On <Finding>, look at data_id and link to file name, line number, parameter
		 * 
		 * Stacktrace to come
		 */
		private void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(true);
	    		saxFindingList.add(finding);
    		}
	    }
		
		
		private String getNativeId(Finding finding) {
			if (finding == null)
				return null;

			String vulnName = null;
			if (finding.getChannelVulnerability() != null)
				vulnName = finding.getChannelVulnerability().getName();
			
			String path = null;
			
			if (finding.getDataFlowElements() != null && !finding.getDataFlowElements().isEmpty()) {
				DataFlowElement sourceElement = finding.getDataFlowElements().get(0);
				path = sourceElement.getSourceFileName() + sourceElement.getLineNumber();
			} else if (finding.getSurfaceLocation() != null) {
				path = finding.getSurfaceLocation().getPath();
			}
			
			String nativeId = hashFindingInfo(vulnName, 
					path, finding.getSurfaceLocation().getParameter());
			
			return nativeId;
		}

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("String".equals(qName)) {
	    		stringValueMap.put(atts.getValue("id"), atts.getValue("value"));
	    	} else if ("File".equals(qName)) {
	    		fileMap.put(atts.getValue("id"), atts.getValue("value"));
	    	} else if ("Site".equals(qName)) {
	    		Map<String, String> newMap = map(
						"fileId", atts.getValue("file_id"),
						"line", atts.getValue("ln"),
						"column", atts.getValue("col"),
						"methodId", atts.getValue("method"),
						"cxt", atts.getValue("cxt"),
						"caller", atts.getValue("caller")
				);
	    		siteMap.put(atts.getValue("id"), newMap);
	    	} else if ("FindingData".equals(qName)) {
	    		Map<String, String> map = map(
						"vulnType", atts.getValue("vtype"),
						"siteId", atts.getValue("site_id"),
						"severity", atts.getValue("sev")
				);
	    		findingDataMap.put(atts.getValue("id"), map);
	    	} else if ("Taint".equals(qName)) {
	    		Map<String, String> map = map(
						"argName", atts.getValue("arg_name"),
						"arg", atts.getValue("arg"),
						"siteId", atts.getValue("site_id")
				);
	    		taintMap.put(atts.getValue("id"), map);
	    	} else if ("Finding".equals(qName)) {
	    		Map<String,String> findingMap = findingDataMap.get(atts.getValue("data_id"));
				if (findingMap == null) {
					throw new IllegalStateRestException("The submitted AppScan Source file has a missing data_id.");
				}
	    		String currentChannelVulnCode = stringValueMap.get(findingMap.get("vulnType"));
	    		String currentPath = fileMap.get(siteMap.get(findingMap.get("siteId")).get("fileId"));
	    		String currentSeverityCode = findingMap.get("severity");
	    		String lineNumberString = siteMap.get(findingMap.get("siteId")).get("line");

				Integer lineNumber = parseInt(lineNumberString, "line");
	    		if (lineNumber == null) {
	    			lineNumber = -1;
	    		}
	    		
	    		Finding finding = constructFinding(currentPath, null, 
	    				currentChannelVulnCode, currentSeverityCode);

                if (finding == null) return;

                finding.setSourceFileLocation(currentPath);
	    		
	    		if (atts.getValue("trace") == null) {
	    			DataFlowElement element = new DataFlowElement(currentPath, lineNumber, null);
	    			finding.setDataFlowElements(list(element));
	    		} else {
	    			finding.setDataFlowElements(getDataFlowElements(atts.getValue("trace")));
	    		}
	    		
	    		String param = parseParameter(finding);
	    		finding.getSurfaceLocation().setParameter(param);
	    		
	    		add(finding);
	    	}
	    }
	    
	    private String parseParameter(Finding finding) {
	    	if (finding == null || finding.getDataFlowElements() == null || 
	    			finding.getDataFlowElements().size() < 1 ||
	    			finding.getDataFlowElements().get(0) == null ||
	    			finding.getDataFlowElements().get(0).getLineText() == null) {
	    		return null;
	    	}
	    	
    		String line = finding.getDataFlowElements().get(0).getLineText();
    		
    		for (Entry<String, String> entry : REGEX_MAP.entrySet()) {
    			if (entry != null && entry.getKey() != null &&
                        line != null &&
    					line.contains(entry.getKey())) {
    				String possibleParameter = RegexUtils.getRegexResult(line, entry.getValue());
    				if (possibleParameter != null) {
    					return possibleParameter;
    				}
    			}
    		}
    		
    		return null;
	    }
	    
	    private Integer parseInt(String maybeInt, String name) {
	    	if (maybeInt == null) {
	    		return null;
	    	}
	    	try {
    			return Integer.parseInt(maybeInt);
    		} catch (NumberFormatException e) {
    			log.warn("AppScan Source importer found a non-integer " +
    					"value of '" + maybeInt + "' in the '" + name + "' number attribute. Continuing.");
    		}
	    	return null;
	    }
	    
	    private List<DataFlowElement> getDataFlowElements(String trace) {
	    	if (trace == null) {
	    		return null;
	    	}
	    	
	    	String[] strings = trace.split("(,|\\.+,|\\.+)");
	    	
	    	List<DataFlowElement> returnList = list();
	    	int count = 1;
	    	for (String string : strings) {
	    		Map<String, String> singleTaintMap = taintMap.get(string);
	    		if (singleTaintMap != null) {
	    			Map<String, String> mySiteMap = siteMap.get(singleTaintMap.get("siteId"));

	    			String lineText = stringValueMap.get(mySiteMap.get("cxt"));
	    			
	    			if (lineText != null) {
		    			DataFlowElement element = new DataFlowElement(
		    					fileMap.get(mySiteMap.get("fileId")), 
		    					parseInt(mySiteMap.get("line"), "line"), 
		    					lineText, 
		    					count++);
		    			returnList.add(element);
	    			}
	    		}
	    	}
	    	
	    	return returnList;
	    }
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AppScanSourceSAXValidator());
	}
	
	public class AppScanSourceSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean noVersion = true;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat || noVersion)
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

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("Finding".equals(qName) && atts.getValue("vuln_type_id") != null) {
	    		hasFindings = true;
			} else if ("AssessmentRun".equals(qName)) {
				noVersion = atts.getValue("version") == null;
				correctFormat = true;
				if (noVersion) {
					LOG.error("No version found in XML. We don't support Ounce scans.");
				}
	    	} else if ("AssessmentStats".equals(qName)) {
	    		testDate = getCalendarFromTimeInMillisString(atts.getValue("date"));
	    		hasDate = testDate != null;
	    	}
	    }
	}
}
