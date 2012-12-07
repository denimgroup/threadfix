////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.channel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * Parses the Microsoft CAT.NET output file.
 * 
 * @author mcollins
 */
// TODO improve by running lots of scans through it and adapting
public class CatNetChannelImporter extends AbstractChannelImporter {
	// this hash is used to keep track of how many times a line has been parsed.
	private Map<String, Integer> paramMap;

	// TODO improve this list - simple as finding out more entry points and
	// their corresponding regular expressions.
	// Since we had so many that were the same except for the numbers, we have
	// stripped the numbers out.
	private static final Map<String, String> ENTRY_POINT_REGEX_MAP = new HashMap<String, String>();
	static {
		ENTRY_POINT_REGEX_MAP.put("stack := stack.{System.Web.UI.WebControls.TextBox}get_Text()",
				"[ +=(]([a-zA-Z0-9_]+)\\.Text");
		ENTRY_POINT_REGEX_MAP.put("stack := stack.{System.Web.HttpRequest}get_Item(stack)",
				"Request\\[\\\"?([a-zA-Z0-9_]+)\\\"?\\]");
		ENTRY_POINT_REGEX_MAP.put("Return from HttpRequest.get_Item",
				"Request\\[\\\"?([a-zA-Z0-9_]+)\\\"?\\]");
	}
	
	private static final Map<String, String> SEVERITIES_MAP = new HashMap<String, String>();
	static {
		SEVERITIES_MAP.put("ACESEC01", "Critical");
		SEVERITIES_MAP.put("ACESEC02", "High");
		SEVERITIES_MAP.put("ACESEC03", "Medium");
		SEVERITIES_MAP.put("ACESEC04", "Medium");
		SEVERITIES_MAP.put("ACESEC05", "Critical");
		SEVERITIES_MAP.put("ACESEC06", "High");
		SEVERITIES_MAP.put("ACESEC07", "High");
		SEVERITIES_MAP.put("ACESEC08", "High");		
	}

	/**
	 * Constructor.
	 * 
	 * @param channelTypeDao
	 *            Spring dependency.
	 * @param channelVulnerabilityDao
	 *            Spring dependency.
	 * @param channelSeverityDao
	 *            Spring dependency.
	 * @param vulnerabilityMapLogDao
	 *            Spring dependency.
	 */
	@Autowired
	public CatNetChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, 
			ChannelSeverityDao channelSeverityDao){
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;

		setChannelType(ChannelType.CAT_NET);

		paramMap = new HashMap<String, Integer>();
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new CatNetSAXParser());
	}

	public class CatNetSAXParser extends DefaultHandler {
		private Boolean getChannelVulnText    = false;
		private Boolean getCodeLineText       = false;
		private Boolean getEntryPointText     = false;
		private Boolean getDataFlowLine       = false;
		private Boolean getIdentifierText     = false;
		private Boolean getDate               = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
		private String currentEntryPoint      = null;
		private String currentCodeLine        = null;
		private String currentNativeId        = null;
		private String currentSourceFileLocation = null;
		
		private String currentDataFlowLineNum  = null;
		private String currentDataFlowFile     = null;
		private String currentDataFlowLineText = null;
		
		private Integer currentSequenceNumber = 0;
						
		private List<DataFlowElement> dataFlowElements = new ArrayList<DataFlowElement>();
	    
		/**
		 * Given a string and an entry point, return the next pertinent parameter.
		 * Uses a hash map to keep track of how many variables have been parsed out
		 * of an input string and entry point, and uses that information to pick the
		 * next one.
		 * 
		 */
		private String getNextParam(String inputString, String entryPoint) {
			if (inputString == null || inputString.equals("") || entryPoint == null
					|| entryPoint.equals("")) {
				return null;
			}

			String entryPointKey = entryPoint.replaceAll("[0-9]", "");
			if (!ENTRY_POINT_REGEX_MAP.containsKey(entryPointKey)) {
				return null;
			}

			String regex = ENTRY_POINT_REGEX_MAP.get(entryPointKey);

			String key = entryPointKey + inputString;
			List<String> stringList = parseParamString(inputString, regex);

			Integer index = getIndex(key, stringList);
			if (index == null) {
				return null;
			} else {
				return (String) stringList.toArray()[index];
			}
		}

		/**
		 * Use a hashmap to keep track of how many times a parameter has been parsed
		 * from a given string / entrypoint pair
		 * 
		 */
		private Integer getIndex(String key, List<String> stringList) {
			Integer index = null;
			if (key != null && stringList != null && stringList.size() > 0) {
				if (paramMap == null) {
					paramMap = new HashMap<String, Integer>();
				}
				// if it has the key, use the next item
				if (paramMap.containsKey(key)) {
					index = paramMap.get(key);
					if (index < stringList.size() - 1) {
						paramMap.put(key, index + 1);
					} else {
						paramMap.put(key, 0);
					}
				} else {
					// otherwise, use the first item. If there are more, store the
					// key.
					index = 0;
					if (stringList.size() != 1) {
						paramMap.put(key, 1);
					}
				}

				return index;
			} else {
				return null;
			}
		}

		/**
		 * Given a regex expression, parse out all occurrences of the regex
		 * 
		 */
		private List<String> parseParamString(String lineText, String regex) {
			if (lineText == null || lineText.trim().equals("") || regex == null
					|| regex.trim().equals("")) {
				return null;
			}

			String editedLineText = lineText;
			
			if (editedLineText.contains("=")) {
				editedLineText = editedLineText.substring(lineText.indexOf('='));
			}

			List<String> retVals = new ArrayList<String>();
			String regexResult = null;

			while (true) {
				regexResult = getRegexResult(editedLineText, regex);
				if (regexResult != null && editedLineText.contains(regexResult)) {
					retVals.add(regexResult);
					editedLineText = editedLineText.substring(editedLineText.indexOf(regexResult) + regexResult.length());
				} else
					break;
			}

			return retVals;
		}

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("Identifier".equals(qName)) {
	    		if (currentChannelVulnCode == null)
	    			getChannelVulnText = true;
	    		else
	    			getIdentifierText = true;
	    	} else if ("Statement".equals(qName)) {
	    		if (currentCodeLine == null)
	    			getCodeLineText = true;
	    		getDataFlowLine = true;
	    	} else if ("EntryPoint".equals(qName) && currentEntryPoint == null) {
	    		getEntryPointText = true;
	    	} else if ("CallResult".equals(qName) || "MethodBoundary".equals(qName)) {
	    		currentDataFlowLineNum = atts.getValue("line");
	    		currentDataFlowFile    = atts.getValue("file");
	    		if (currentSourceFileLocation == null)
	    			currentSourceFileLocation = atts.getValue("file");
	    		currentUrlText = convertSourceFileNameToUrl(currentSourceFileLocation, 
	    				applicationChannel.getApplication().getProjectRoot());
	    	} else if ("StartTimeStamp".equals(qName)) {
	    		getDate = true;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("CallResult".equals(qName) || "MethodBoundary".equals(qName)) {
	    		
	    		Integer lineNum = null;
	    		
	    		try {
	    			lineNum = Integer.valueOf(currentDataFlowLineNum);
	    		} catch (NumberFormatException e) {
	    			log.error("CAT.NET file contained a non-numeric value in its line number field.");
	    		}
	    		
	    		DataFlowElement newElement = new DataFlowElement(currentDataFlowFile, 
	    				lineNum, currentDataFlowLineText, currentSequenceNumber);

	    		if (dataFlowElements != null)
	    			dataFlowElements.add(newElement);
	    		else {
	    			dataFlowElements = new ArrayList<DataFlowElement>();
	    			dataFlowElements.add(newElement);
	    		}
	    		
	    		currentSequenceNumber += 1;
	    		currentDataFlowLineNum = null;
	    		currentDataFlowFile = null;
	    		currentDataFlowLineText = null;
	    	} else if ("Rule".equals(qName)) {
	    		currentChannelVulnCode = null;
	    	} else if ("Result".equals(qName)) {
	    		Finding finding = constructFinding(currentUrlText, getNextParam(currentCodeLine, currentEntryPoint), 
	    				currentChannelVulnCode, SEVERITIES_MAP.get(currentChannelVulnCode));
	    		
	    		finding.setNativeId(currentNativeId);
	    		finding.setDataFlowElements(dataFlowElements);
	    		finding.setSourceFileLocation(currentSourceFileLocation);
	    		
	    		finding.setIsStatic(true);
	    		
	    		saxFindingList.add(finding);
	    		
	    		currentSourceFileLocation = null;
	    		currentSequenceNumber = 0;
	    		currentCodeLine = null;
	    		currentEntryPoint = null;
	    		currentUrlText = null;
	    		currentNativeId = null;
	    		dataFlowElements = new ArrayList<DataFlowElement>();
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getDataFlowLine) {
	    		currentDataFlowLineText = getText(ch, start, length);
	    		getDataFlowLine = false;
	    	}
	    	
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getText(ch, start, length);
	    		getChannelVulnText = false;
	    	} else if (getCodeLineText) {
	    		currentCodeLine = getText(ch, start, length);
	    		getCodeLineText = false;
	    	} else if (getEntryPointText) {
	    		currentEntryPoint = getText(ch, start, length);
	    		getEntryPointText = false;
	    	} else if (getIdentifierText) {
	    		currentNativeId = getText(ch, start, length);
	    		getIdentifierText = false;
	    	} else if (getDate) {
	    		date = getCalendarFromString("EEE, MMM dd, yyyy hh:mm:ss aa", getText(ch, start, length));
	    		getDate = false;
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new CatNetSAXValidator());
	}
	
	public class CatNetSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
		private boolean getDate = false;
		
		private boolean report = false, analysis = false, rules = false;
		
	    private void setTestStatus() {
	    	correctFormat = (report && analysis && rules);
	    	
	    	if (!correctFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings)
	    		testStatus = EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (!hasDate && "StartTimeStamp".equals(qName)) {
	    		getDate = true;
	    	}
	    	
	    	if ("Report".equals(qName)) {
	    		report = true;
	    	} else if ("Analysis".equals(qName)) {
	    		analysis = true;
	    	} else if ("Rules".equals(qName)) {
	    		rules = true;
	    	}
	    	
	    	if (!hasFindings && "Result".equals(qName)) {
	    		hasFindings = true;	
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		testDate = getCalendarFromString("EEE, MMM dd, yyyy hh:mm:ss aa", getText(ch, start, length));
	    		getDate = false;
	    		hasDate = true;
	    	}
	    }
	}
	
}
