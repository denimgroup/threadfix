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
package com.denimgroup.threadfix.plugin.scanner.service.channel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
@PluginImplementation
public class AppScanSourceChannelImporter extends AbstractChannelImporter {

	@Override
	public String getType() {
		return ScannerType.APPSCAN_SOURCE.getFullName();
	}
	
	private static final Map<String, String> REGEX_MAP = new HashMap<>();
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
		super(ScannerType.APPSCAN_SOURCE.getFullName());
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
		
		private Map<String, String> stringValueMap = new HashMap<>();
		// String.id -> String.value
		private Map<String, String> fileMap = new HashMap<>();
		// File.id -> File.value
		private Map<String, Map<String,String>> siteMap = new HashMap<>();
		// Site.id -> ("fileId" -> File.id, "line" -> File.ln, "column" -> Site.col, "methodId" -> Site.method)
		private Map<String, Map<String, String>> findingDataMap = new HashMap<>();
		// FindingData.id -> ("vulnType" -> FindingData.vtype, "siteId" -> FindingData.site_id, "sev" -> FindingData.sev)
		private Map<String, Map<String, String>> taintMap = new HashMap<>();
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
	    		Map<String, String> map = new HashMap<>();
	    		map.put("fileId", atts.getValue("file_id"));
	    		map.put("line", atts.getValue("ln"));
	    		map.put("column", atts.getValue("col"));
	    		map.put("methodId", atts.getValue("method"));
	    		map.put("cxt", atts.getValue("cxt"));
	    		map.put("caller", atts.getValue("caller"));
	    		siteMap.put(atts.getValue("id"), map);
	    	} else if ("FindingData".equals(qName)) {
	    		Map<String, String> map = new HashMap<>();
	    		map.put("vulnType", atts.getValue("vtype"));
	    		map.put("siteId", atts.getValue("site_id"));
	    		map.put("severity", atts.getValue("sev"));
	    		findingDataMap.put(atts.getValue("id"), map);
	    	} else if ("Taint".equals(qName)) {
	    		Map<String, String> map = new HashMap<>();
	    		map.put("argName", atts.getValue("arg_name"));
	    		map.put("arg", atts.getValue("arg"));
	    		map.put("siteId", atts.getValue("site_id"));
	    		taintMap.put(atts.getValue("id"), map);
	    	} else if ("Finding".equals(qName)) {
	    		Map<String,String> findingMap = findingDataMap.get(atts.getValue("data_id"));
	    		String currentChannelVulnCode = stringValueMap.get(findingMap.get("vulnType"));
	    		String currentPath = fileMap.get(siteMap.get(findingMap.get("siteId")).get("fileId"));
	    		String currentSeverityCode = findingMap.get("severity");
	    		String lineNumberString = fileMap.get(siteMap.get(findingMap.get("siteId")).get("line"));
	    		
	    		Integer lineNumber = parseInt(lineNumberString, "line");
	    		if (lineNumber == null) {
	    			lineNumber = -1;
	    		}
	    		
	    		Finding finding = constructFinding(currentPath, null, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		finding.setSourceFileLocation(currentPath);
	    		
	    		if (atts.getValue("trace") == null) {
	    			DataFlowElement element = new DataFlowElement(currentPath, lineNumber, null);
	    			finding.setDataFlowElements(Arrays.asList(element));
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
    				String possibleParameter = getRegexResult(line, entry.getValue());
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
	    	
	    	List<DataFlowElement> returnList = new ArrayList<>();
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
	
	public static String getRegexResult2(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty()) {
			return null;
		}

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
	}
	
	@Override
	public ScanCheckResultBean checkFile() {
		return new ScanCheckResultBean(ScanImportStatus.SUCCESSFUL_SCAN);
		
		//return testSAXInput(new AppScanSourceSAXValidator());
	}
	
	public class AppScanSourceSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
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
	    	} else if ("AssessmentFile".equals(qName)) {
	    		correctFormat = true;
	    	} else if ("AssessmentStats".equals(qName)) {
	    		testDate = getCalendarFromTimeInMillisString(atts.getValue("date"));
	    		hasDate = testDate != null;
	    	}
	    }
	}
}
