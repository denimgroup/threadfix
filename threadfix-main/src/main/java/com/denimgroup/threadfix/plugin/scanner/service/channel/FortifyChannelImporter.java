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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.StaticPathInformation;
import com.denimgroup.threadfix.service.ScanUtils;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * Parses the SCA Fortify fpr output file.
 */
@PluginImplementation
public class FortifyChannelImporter extends AbstractChannelImporter {

	// TODO run through more files and determine whether this method is still valuable
	// or whether we can use only the 'action' parameter and the column parsing.
	private static final Map<String, String> FACT_REGEX_MAP = new HashMap<>();
	private static final Map<String, String> SPECIAL_REGEX_MAP = new HashMap<>();
	static {
		FACT_REGEX_MAP.put("Direct : System.Web.HttpRequest.get_Item",
				"Request\\[\"([a-zA-Z0-9_]+)\"\\]");
		FACT_REGEX_MAP.put("Direct : System.Web.UI.WebControls.TextBox.get_Text",
				"([a-zA-Z0-9_]+)\\.Text");
		FACT_REGEX_MAP.put("Direct : javax.servlet.ServletRequest.getParameter",
				"getParameter\\(\"([a-zA-Z0-9_]+)\"\\)");
		FACT_REGEX_MAP.put("Direct : System.Data.Common.DbDataReader.get_Item",
				"reader\\[\"([a-zA-Z0-9_]+)\"\\]");
		FACT_REGEX_MAP.put("Direct : System.Web.UI.WebControls.Label.set_Text",
				"^\\s*([a-zA-Z0-9_]+).Text");
		FACT_REGEX_MAP.put("Direct : Customer.HydrateCustomer",
				"Customer.HydrateCustomer\\(([a-zA-Z0-9_]+)\\)");
		FACT_REGEX_MAP.put("get_Item(return)", "Request\\[\"([a-zA-Z0-9_]+)\"\\]");
		FACT_REGEX_MAP.put("get_Item()", "Request\\[\"([a-zA-Z0-9_]+)\"\\]");
		FACT_REGEX_MAP.put("get_Item(...) : HttpSessionState.get_Item may return NULL",
				"Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		FACT_REGEX_MAP.put("get_Text(return)", "([a-zA-Z0-9_]+).Text");
		FACT_REGEX_MAP.put("get_QueryString(return)", "Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		FACT_REGEX_MAP.put("WEB, XSS",
				"action=\\\"<\\%= ?Request.([a-zA-Z0-9_]+) ?\\%>\\\"");
		FACT_REGEX_MAP.put("Direct : builtin_echo",
				"POST\\[\"?([a-zA-Z0-9_]+)\"?\\]");// TODO LOOK AT THIS
		FACT_REGEX_MAP.put("Direct : System.Web.HttpRequest.get_RawUrl",
				"Request.([a-zA-Z0-9_]+)");
		FACT_REGEX_MAP.put("Name: System.Web.SessionState.HttpSessionState.set_Item",
				" *([a-zA-Z0-9_\\.]+\\[\\\"[a-zA-Z0-9_]+\\\"\\])");
		FACT_REGEX_MAP.put("Direct : System.IO.TextWriter.Write",
				"<% ?=? ?([a-zA-Z0-9_]+) ?%>");
		FACT_REGEX_MAP.put("ReadToEnd()", "([a-zA-Z0-9_]+)\\.ReadToEnd\\(\\)");
		FACT_REGEX_MAP.put("GetSqlStringCommand()",
				"Database\\.GetSqlStringCommand\\(([a-zA-Z0-9_]+)");
		FACT_REGEX_MAP.put("Direct : System.Web.SessionState.HttpSessionState.set_Item",
				"Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		FACT_REGEX_MAP.put("read request",
				"[rR]equest\\.?[a-zA-Z_]*\\(\\\"?([a-zA-Z0-9_]+)\\\"?\\)");
		FACT_REGEX_MAP.put("Direct : connection.execute",
				"\\.[eE]xecute\\(([a-zA-Z0-9_]+)\\)");
		FACT_REGEX_MAP.put("Direct : response.write",
				"<\\% ?=? ?([ a-zA-Z0-9_\\.\\\"\\(\\)]+) ?\\%>\\\"");
		FACT_REGEX_MAP.put("Direct : fopen",
				"fopen\\(\"?($?[a-zA-Z0-9_]+)\"?\\)");
		FACT_REGEX_MAP.put("Direct : system",
				"system\\(\"?($?[a-zA-Z0-9_]+)\"?\\)");
		FACT_REGEX_MAP.put("Direct : System.Data.SqlClient.SqlCommand.SqlCommand", 
				"SqlCommand\\($?\"?([a-zA-Z0-9_]+)\"?\\)");
		
		SPECIAL_REGEX_MAP.put("get_Item", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		SPECIAL_REGEX_MAP.put("get_Item()", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		SPECIAL_REGEX_MAP.put("get_Text", "=.*?([a-zA-Z0-9_]+)\\.[tT]ext");
		SPECIAL_REGEX_MAP.put("get_Text()", "=.*?([a-zA-Z0-9_]+)\\.[tT]ext");
		SPECIAL_REGEX_MAP.put("Write", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
		SPECIAL_REGEX_MAP.put("getParameter", "getParameter\\(\"([a-zA-Z0-9\\._]+)\"\\)");
		SPECIAL_REGEX_MAP.put("getHeader", "getHeader\\(\"([a-zA-Z0-9\\._]+)\"\\)");
	}
	
	public FortifyChannelImporter() {
		super(ScannerType.FORTIFY.getFullName());
		doSAXExceptionCheck = false;
	}

	private int getNumber(String input) {
		if (input == null) {
			return -1;
		}
		try {
			return Integer.parseInt(input);
		} catch (NumberFormatException e) {
			log.warn("Got an invalid value '" + input + "' for what should have been a number", e);
			return -1;
		}
	}

	@Override
	@Transactional
	public Scan parseInput() {
		InputStream auditXmlStream = null;
		InputStream fvdlInputStream = null;

		zipFile = unpackZipStream();

		auditXmlStream = getFileFromZip("audit.xml");
		fvdlInputStream = getFileFromZip("audit.fvdl");

		if (zipFile == null || fvdlInputStream == null)
			return null;

		inputStream = fvdlInputStream;
		Scan returnScan = parseSAXInput(new FortifySAXParser());
		Calendar auditXmlDate = getTime(auditXmlStream);
		if (returnScan != null) {
			if (auditXmlDate == null) {
				returnScan.setImportTime(date);
			} else {
				returnScan.setImportTime(auditXmlDate);
			}
		}
		
		return returnScan;
	}

	/**
	 * The strategy for this SAX parser requires two steps 
	 * because information appearing after the normal
	 * vulnerability information is required to fully process the
	 * vulnerabilities. First we record all of the information in 
	 * custom data structures composed of Maps and Lists, then it is
	 * transformed at the end using the expandFindings() method to the
	 * ThreadFix entity data structures.
	 * 
	 * @author mcollins
	 */
	public class FortifySAXParser extends HandlerWithBuilder {
				
		/**
		 * This variable is used to keep track of whether a finding has had a parameter parsed.
		 */
		boolean paramParsed = false;
		
		/**
		 * This variable is used to keep track of the variable that had a value assigned 
		 * to it in the last line so that we do not set it as a parameter.
		 */
		String lastLineVariable = null;
		
		// maybe bad idea? Complicated data structure.
		// the String key is the native ID and the Maps in the List 
		// have the information for DataFlowElements
		Map<String, List<DataFlowElementMap>> nativeIdDataFlowElementsMap = new HashMap<>();
		Map<String, StaticPathInformation> staticPathInformationMap = new HashMap<>();
		
		List<Map<String,String>> rawFindingList = new ArrayList<>();
		
		List<DataFlowElementMap> dataFlowElementMaps = new ArrayList<>();
		DataFlowElementMap currentMap = null;
		StaticPathInformation currentStaticPathInformation = null;
		
		Map<String, DataFlowElementMap> nodeSnippetMap = new HashMap<>();
		
		Map<String, Map<String, Float>> ruleMap = new HashMap<>();
		String currentRuleID = null;
		
		String currentChannelType = null;
		String currentChannelSubtype = null;
		String currentSeverity = null;
		String currentNativeId = null;
		String currentPath = null;
		String currentParameter = null;
		String currentConfidence = null;
		String currentClassID = null;
		
		String nodeId = null;
		
		Map<String, String> snippetMap = new HashMap<>();
		String snippetId = null;
		int lineCount = 0;
		boolean getSnippetText = false;
		
		boolean getFact = false;
		boolean getChannelType = false;
		boolean getChannelSubtype = false;
		boolean getSeverity = false;
		boolean getStaticPathInformationUrl = false;
		boolean getNativeId = false;
		boolean getAction = false;
		boolean getImpact = false, getProbability = false, getAccuracy = false;
		boolean getConfidence = false;
		boolean getClassID = false;
		
		boolean skipToNextVuln = false;
		boolean doneWithVulnerabilities = false;
		
	    public void addToList() {
	    	Map<String,String> findingMap = new HashMap<>();
	    	
	    	if (currentChannelType != null && currentChannelSubtype != null && 
	    			!currentChannelSubtype.trim().equals("")) {
	    		currentChannelType = currentChannelType + ": " + currentChannelSubtype;
	    	}
	    	
	    	
	    	findingMap.put("channelType", currentChannelType);
	    	findingMap.put("severity",currentSeverity);
	    	findingMap.put("nativeId", currentNativeId);
	    	findingMap.put("confidence", currentConfidence);
	    	findingMap.put("classID", currentClassID);
	    	staticPathInformationMap.put(currentNativeId, currentStaticPathInformation);
	    	nativeIdDataFlowElementsMap.put(currentNativeId, dataFlowElementMaps);
	    	
	    	rawFindingList.add(findingMap);
	    	
	    	currentChannelType = null;
	    	currentChannelSubtype = null;
			currentSeverity = null;
			currentNativeId = null;
			currentConfidence = null;
			currentClassID = null;
			currentStaticPathInformation = null;
			dataFlowElementMaps = new ArrayList<>();
			currentMap = null;
	    }
	    
	    public void expandFindings() {
	    	String nativeId = null;
	    	
	    	for (Map<String, String> findingMap : rawFindingList) {
	    		nativeId = findingMap.get("nativeId");
	    		
	    		List<DataFlowElementMap> dataFlowElementMaps = 
	    			nativeIdDataFlowElementsMap.get(nativeId);
	    		
	    		List<DataFlowElement> dataFlowElements = parseDataFlowElements(dataFlowElementMaps);
	    		
	    		StaticPathInformation staticPathInformation = staticPathInformationMap.get(nativeId);
	    		
	    		String severity = getSeverityName(getFloatOrNull(findingMap.get("confidence")),
	    				ruleMap.get(findingMap.get("classID")));
	    			    		
	    		if (severity == null) {
	    			severity = findingMap.get("severity");
	    		}
	   
	    		Finding finding = constructFinding(currentPath, currentParameter,
	    				findingMap.get("channelType"), severity);
	    			    		
	    		finding.setNativeId(nativeId);
	    		finding.setDataFlowElements(dataFlowElements);
	    		finding.setIsStatic(true);
	    		finding.setSourceFileLocation(currentPath);
	    		finding.setStaticPathInformation(staticPathInformation);
	    		
	    		saxFindingList.add(finding);
	    		
	    		// re-initialize everything
	    		currentPath = null;
	    		currentParameter = null;
				currentChannelType = null;
				currentSeverity = null;
				nativeId = null;
	    	}
	    }

	    private String getSeverityName(Float confidence, Map<String, Float> map) {
			if (confidence != null && map != null && map.get("Impact") != null && 
					map.get("Probability") != null && map.get("Accuracy") != null)  {
				
				Float impact = map.get("Impact");
				Float likelihood = (float) (confidence * map.get("Accuracy") * map.get("Probability")) / 25;

				
				// TODO figure out what we should actually be doing here.
				// This comes from the Fortify training materials and *almost* works with our sample files.
				if (impact >= 2.5) {
					if (likelihood < 2.795) {
						return "High";
					} else {
						return "Critical";
					}
				} else {
					if (likelihood < 2.795) {
						return "Low";
					} else {
						return "Medium";
					}
				}
			}
			return null;
		}

		public List<DataFlowElement> parseDataFlowElements(List<DataFlowElementMap> dataFlowElementMaps) {
	    	int index = 0;
	    	String lastNode = null;
	    	
	    	
	    	List<DataFlowElement> dataFlowElements = new ArrayList<>();
	    	
	    	for (DataFlowElementMap dataFlowElementMap : dataFlowElementMaps) {
	    		
	    		// Don't repeat nodes
	    		if (lastNode != null && lastNode.equals(dataFlowElementMap.node)) {
	    			continue;
	    		}
	    		
	    		// merge results with the information from snippets
    			DataFlowElement dataFlowElement = new DataFlowElement();
    			if (dataFlowElementMap.node != null) {
    				DataFlowElementMap nodeMap = nodeSnippetMap.get(
    						dataFlowElementMap.node);
    				    				
    				if (nodeMap != null) {
    					dataFlowElementMap.merge(nodeMap);
    					lastNode = dataFlowElementMap.node;
    				} else {
    					continue;
    				}
    			}
    			
    			// Grab information from the temporary data structure
    			if (dataFlowElementMap.snippet != null) {
    				dataFlowElement.setLineText(
    						snippetMap.get(dataFlowElementMap.snippet));
    			}
    			dataFlowElement.setLineNumber(getNumber(dataFlowElementMap.line));
    			dataFlowElement.setColumnNumber(getNumber(dataFlowElementMap.column));

    			if (dataFlowElementMap.fileName != null &&
    					!dataFlowElementMap.fileName.trim().equals("")) {
    				dataFlowElement.setSourceFileName(dataFlowElementMap.fileName);
    				currentPath = dataFlowElementMap.fileName;
    			}
    			
    			if (dataFlowElement.getSourceFileName() == null || 
    					dataFlowElement.getSourceFileName().trim().equals("") ||
    					dataFlowElement.getLineText() == null ||
    					dataFlowElement.getLineText().trim().equals("")) {
    				continue;
    			}
    			
    			dataFlowElement.setSequence(index++);
    			
    			// Attempt to parse a parameter
    			if (!paramParsed) {
    				
    				// First try the given Fact
	    			if (currentParameter == null &&
	    					dataFlowElementMap.snippet != null && 
	    					dataFlowElementMap.fact != null) {
	    				String line = snippetMap.get(dataFlowElementMap.snippet);
	    				
	    				if (FACT_REGEX_MAP.containsKey(dataFlowElementMap.fact)) {
	    					currentParameter = getRegexResult(line, 
	    							FACT_REGEX_MAP.get(dataFlowElementMap.fact));
	    				}
	    				
	    				// Try to get it out by simply looking at the column and grabbing 
	    				// the parameter if it is alphanumeric
	    				if (currentParameter == null &&
	    						dataFlowElement.getColumnNumber() != 0) {
	    					String fragment = line.substring(dataFlowElement.getColumnNumber() - 1);
	    					if (fragment != null && fragment.trim().endsWith(");")) {
	    						
	    						if (currentParameter == null) {
	        						currentParameter = fragment.trim().replaceFirst("\\);$", "");
	        						if (!currentParameter.equals(
	        								getRegexResult(currentParameter, "^([a-zA-Z_0-9]+)$"))) {
	        							currentParameter = null;
	        						}
	        					}
	    					}
	    				}
	    			}
	    			
	    			// Otherwise try to get it out by using information from the Action tag
					// This tag gives the function call and sometimes the position of the
					// parameter.
					if ((currentParameter == null || currentParameter.trim().equals("")) &&
							dataFlowElementMap.action != null &&
							dataFlowElementMap.snippet != null) {
						
						String line = snippetMap.get(dataFlowElementMap.snippet);
						String action = dataFlowElementMap.action;
						
						if (line != null && action != null) {
							currentParameter = getParameterName(action,line,dataFlowElement.getColumnNumber());
						}
					}

					paramParsed = currentParameter != null;
					
					if (lastLineVariable != null &&
							currentParameter != null &&
							lastLineVariable.contains(currentParameter.trim())) {
						currentParameter = null;
					}
					
					if (!paramParsed && dataFlowElementMap.snippet != null) {
						lastLineVariable = getRegexResult(snippetMap.get(dataFlowElementMap.snippet), "^([^=]+)=");
						if (lastLineVariable != null) {
							lastLineVariable = lastLineVariable.trim();
						}
					}
    			}
				
    			dataFlowElements.add(dataFlowElement);
    		}
	    	
	    	paramParsed = false;
	    		    	
	    	return dataFlowElements;
	    }
	    
	    /**
		 * TODO clean up / improve
		 * @param action
		 * @param line
		 * @param column
		 * @return the resulting parameter
		 */
		private String getParameterName(String action, String line, int column) {
			boolean tookOutReturn = false;
			
			String parameter = null;
			
			String functionName = getRegexResult(action, "^([^?\\(\\[]*)");
			if (functionName == null){
				return null;
			}
			
			String argument = getRegexResult(action, functionName + "\\(\"?([^\"]+\"?)\\)");
			
			if ("main".equals(functionName)) {
				paramParsed = true;
			}
			
			if (argument == null
			 	 || "this.myName".equals(argument)
				 || "error".equals(functionName)
				 || "main".equals(functionName)) {
				return null;
			}

			boolean isObjectOfCall = argument.startsWith("this");
			
			String strippedNumbers = getRegexResult(argument, "^([0-9]+)");
			
			if (argument.contains(" : return")) {
				tookOutReturn = true;
				argument = argument.replaceAll(" : return\\[?\\]?","");
			}
			int number = getNumber(strippedNumbers);
			
			if (argument != null) {
				
				if (SPECIAL_REGEX_MAP.containsKey(functionName)) {
					parameter = getRegexResult(line,SPECIAL_REGEX_MAP.get(functionName));
				}
				
				if (parameter == null && isObjectOfCall) {
					parameter = getRegexResult(line, "([a-zA-Z0-9_\\[]+\\]?)\\." + functionName);
				} else if (number != -1) {
					if (line.contains(functionName)) {
						String commas = "";
						while (number-- != 0) {
							commas = commas + "[^,]+,";
						}
						
						String paramRegex = "([^,\\)]+)";
						
						parameter = getRegexResult(line, functionName + "\\(" + commas + paramRegex);
						
						if (tookOutReturn) {
							String testParameter = getRegexResult(parameter, 
									"\\([ ]*([a-zA-Z0-9_]+)(?:\\.Text)?[ ]*\\)?$");
							if (testParameter != null) {
								parameter = testParameter;
							}

							tookOutReturn = false;
						}
					} else if (functionName.equals("Concat")) {
						String regex = "([^\\+]*[^;\\+])";
						while (number-- != 0) {
							regex = "[^\\+]*\\+" + regex;
						}
						regex = "^[^=]+= ?" + regex;
						String result = getRegexResult(line,regex);
						
						if (result != null && !result.startsWith("\"")
								&& !result.trim().equals("")) {
							parameter = result;
						}
					} 
				}
			}

			if (parameter == null) {
				return null;
			}
			
			paramParsed = true;
			
			// This section checks to see if the result is a call to getParameter()
			// if it is, then we can get a valid web parameter out of it.
			String requestParameter = getRegexResult(parameter, 
					".getParameter\\(\"?([a-zA-Z0-9_]+)\"?\\)");
			
			// also try GET[] or POST[]
			if (requestParameter == null) {
				requestParameter = getRegexResult(parameter, 
				"(?:GET|POST)\\[\"([a-zA-Z0-9_]+)\"\\]");
			}
			
			if (requestParameter != null && !requestParameter.trim().equals("")) {
				parameter = requestParameter;
			}
			
			// if it passes any of these conditions we probably don't want it
			if (parameter.endsWith("(") || parameter.endsWith("\"") || parameter.endsWith(")") ||
					parameter.startsWith("(") || parameter.startsWith("\"") || parameter.contains("+")) {
				parameter = null;
			}
						
			return parameter;
		}
	   
	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
		@Override
		public void endDocument() {
			nativeIdDataFlowElementsMap = null;
			rawFindingList = null;
			dataFlowElementMaps = null;
			nodeSnippetMap = null;
		}
		
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if (!doneWithVulnerabilities) {
		    	if ("Type".equals(qName)) {
		    		skipToNextVuln = false;
		    		getChannelType = true;
		    	} else if ("Subtype".equals(qName)) {
		    		getChannelSubtype = true;
		    	} else if ("InstanceSeverity".equals(qName)) {
		    		getSeverity = true;
		    	} else if (currentStaticPathInformation != null && "URL".equals(qName)) {
		    		getStaticPathInformationUrl = true;
		    	} else if ("InstanceID".equals(qName)) {
		    		getNativeId = true;
		    	} else if ("ClassID".equals(qName)) {
		    		getClassID = true;
		    	} else if ("Confidence".equals(qName)) {
		    		getConfidence = true;
		    	} else if (!skipToNextVuln && "Entry".equals(qName)) {
		    		if (atts.getValue("name") != null && atts.getValue("type") != null) {
		    			currentStaticPathInformation = new StaticPathInformation();
		    			currentStaticPathInformation.setName(atts.getValue("name"));
		    			currentStaticPathInformation.setType(atts.getValue("type"));
		    		} else {
		    			currentMap = new DataFlowElementMap();
		    		}
		    	} else if (currentMap != null && "NodeRef".equals(qName)) {
		    		currentMap.node = atts.getValue("id");
		    	} else if (currentMap != null && "SourceLocation".equals(qName)) {
		    		currentMap.line = atts.getValue("line");
		    		currentMap.column = atts.getValue("colStart");
		    		currentMap.snippet = atts.getValue("snippet");
		    		currentMap.fileName = atts.getValue("path");
		    	} else if (!skipToNextVuln && "Fact".equals(qName) && "Call".equals(atts.getValue("type"))){
		    		getFact = true;
		    	} else if ("CreatedTS".equals(qName) && atts.getValue("date") != null
		    			&& atts.getValue("time") != null) {
		    		String dateString = atts.getValue("date") + " " + atts.getValue("time");
		    		date = getCalendarFromString("yyyy-MM-dd hh:mm:ss", 
		    				dateString);
		    	}
	    	} else {
	    		if ("Node".equals(qName)) {
	    			nodeId = atts.getValue("id");
	    		} else if ("SourceLocation".equals(qName)) {
	    			DataFlowElementMap currentNodeMap = new DataFlowElementMap();
	    			
	    			currentNodeMap.line = atts.getValue("line");
	    			currentNodeMap.column = atts.getValue("colStart");
	    			currentNodeMap.snippet = atts.getValue("snippet");
	    			currentNodeMap.fileName = atts.getValue("path");
	    			nodeSnippetMap.put(nodeId, currentNodeMap);
	    		} else if ("Snippet".equals(qName)){
	    			snippetId = atts.getValue("id");
	    		} else if ("Action".equals(qName) && atts.getValue("type") != null &&
	    				atts.getValue("type").endsWith("Call")){
	    			getAction = true;
	    		} else if ("Text".equals(qName)) {
	    			getSnippetText = true;
	    		} else if ("Rule".equals(qName)) {
	    			if (!ruleMap.containsKey(atts.getValue("id"))) {
	    				currentRuleID = atts.getValue("id");
	    				ruleMap.put(currentRuleID, new HashMap<String, Float>());
	    			}
	    		} else if (currentRuleID != null && "Group".equals(qName) &&
	    				atts.getValue("name") != null) {
	    			 if (atts.getValue("name").equals("Impact")) {
	    				 getImpact = true;
	    			 } else if (atts.getValue("name").equals("Probability")) {
	    				 getProbability = true;
	    			 } else if (atts.getValue("name").equals("Accuracy")) {
	    				 getAccuracy = true;
	    			 }
	    		}
	    	}
	    }

	    public void endElement (String uri, String name, String qName) throws SAXException
	    {
	    	if (getChannelType) {
	    		currentChannelType = getBuilderText();
	    		getChannelType = false;
	    	} else if (getSeverity) {
	    		currentSeverity = getBuilderText();
	    		getSeverity = false;
	    	} else if (getNativeId) {
	    		currentNativeId = getBuilderText();
	    		getNativeId = false;
	    	} else if (getClassID) {
	    		currentClassID = getBuilderText();
	    		getClassID = false;
	    	} else if (getFact) {
	    		currentMap.fact = getBuilderText();
	    		getFact = false;
	    	} else if (getStaticPathInformationUrl) {
	    		currentStaticPathInformation.setValue(getBuilderText());
	    		getStaticPathInformationUrl = false;
	    	} else if (getSnippetText){
	    		String fullText = getBuilderText();
	    		
	    		if (fullText != null && fullText.contains("\n")) {
		    		String[] split = fullText.split("\n");
		    		if (split != null && split.length > 3) {
		    			snippetMap.put(snippetId,split[3]);
		    		}
	    		}
	    		getSnippetText = false;
	    		snippetId = null;
	    	} else if (getChannelSubtype) {
	    		currentChannelSubtype = getBuilderText();
	    		getChannelSubtype = false;
	    	} else if (getAction) {
	    		getAction = false;
	    		if (nodeId != null && nodeSnippetMap.get(nodeId) != null) {
	    			nodeSnippetMap.get(nodeId).action = getBuilderText();
	    		}
	    	} else if (getImpact) {
	    		ruleMap.get(currentRuleID).put("Impact", getFloatOrNull(getBuilderText()));
	    		getImpact = false;
	    	} else if (getProbability) {
	    		ruleMap.get(currentRuleID).put("Probability", getFloatOrNull(getBuilderText()));
	    		getProbability = false;
	    	} else if (getAccuracy) {
	    		ruleMap.get(currentRuleID).put("Accuracy", getFloatOrNull(getBuilderText()));
	    		getAccuracy = false;
	    	} else if (getConfidence) {
	    		currentConfidence = getBuilderText();
	    		getConfidence = false;
	    	}
	    	
	    	if (!doneWithVulnerabilities) {
		    	if ("Vulnerability".equals(qName)) {
		    		addToList();
		    	} else if ("Vulnerabilities".equals(qName)) {
		    		doneWithVulnerabilities = true;
		    	} else if ("Entry".equals(qName) || "Configuration".equals(qName)) {
		    		if (currentMap != null) {
		    			dataFlowElementMaps.add(currentMap);
		    			currentMap = null;
		    		}
		    	} else if ("ExternalEntries".equals(qName)) {
		    		skipToNextVuln = true;
		    		currentMap = null;
		    	}
	    	} else if ("RuleInfo".equals(qName)) {
    			expandFindings();
    			// TODO determine whether this exception actually is any faster
    			throw new SAXException("Done Parsing.");
    		} else if ("Rule".equals(qName)) {
    			currentRuleID = null;
    		}
	    }
	    
	    public void characters (char ch[], int start, int length) 
	    {
	    	if (getChannelType || getSeverity || getNativeId || getClassID || getFact 
	    			|| getSnippetText || getChannelSubtype || getAction || getImpact ||
	    			getProbability || getAccuracy || getConfidence || getStaticPathInformationUrl) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
	
	private Float getFloatOrNull(String s) {
		if (s == null) {
			return null;
		}
		
		try {
			return Float.valueOf(s);
		} catch (NumberFormatException e) {
			log.warn("Encountered a non-float value for a float field in the Fortify FPR. This shouldn't happen.", e);
			return null;
		}
	}
	    
	@Override
	public ScanCheckResultBean checkFile() {
		InputStream auditXmlStream = null;
		InputStream fvdlInputStream = null;

		zipFile = unpackZipStream();
		auditXmlStream = getFileFromZip("audit.xml");
		fvdlInputStream = getFileFromZip("audit.fvdl");

		if (zipFile == null || fvdlInputStream == null)
			return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);
						
		testDate = getTime(auditXmlStream);
		
		inputStream = fvdlInputStream;
		return testSAXInput(new FortifySAXValidator());
	}

	public class FortifySAXValidator extends DefaultHandler {
		
		private boolean hasFindings = false;
		private boolean correctFormat = false;
		
		private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (testDate != null)
	    		testStatus = checkTestDate();
	    	if (ScanImportStatus.SUCCESSFUL_SCAN == testStatus && !hasFindings)
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

	    public void startElement (String uri, String name, String qName, Attributes atts) 
	    		throws SAXException {	    	
	    	if ("FVDL".equals(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if (testDate == null && "CreatedTS".equals(qName) 
	    			&& atts.getValue("date") != null
	    			&& atts.getValue("time") != null) {
	    		testDate = getCalendarFromString("yyyy-MM-dd hh:mm:ss", 
	    				atts.getValue("date") + " " + atts.getValue("time"));
	    	}
	    	
	    	if ("Vulnerability".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
	
	public Calendar getTime(InputStream stream) {
		if (stream == null) {
			return null;
		}
		
		inputStream = stream;
		FortifyTimeParser timeParser = new FortifyTimeParser();
		ScanUtils.readSAXInput(timeParser, FILE_CHECK_COMPLETED, stream);
		
		return timeParser.resultTime;
	}

	public class FortifyTimeParser extends HandlerWithBuilder {
		Calendar resultTime = null;
		boolean getDate = false;

	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("WriteDate".equals(qName)) { 
	    		getDate = true; 
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String stringTime = getBuilderText();
	    		if (stringTime != null) {
	    			int index = stringTime.indexOf('.');
	    			if (index != -1) {
		    			resultTime = getCalendarFromString("yyyy-MM-dd'T'hh:mm:ss", 
		    					stringTime.substring(0,index));
	    			}
	    		}
	    		getDate = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
		}
	}
	
	// This should be more space-efficient (and time-efficient) 
	// than the Map<String, String> interface
	class DataFlowElementMap {
		String line = null, column = null, lineText = null, fileName = null, 
			node = null, snippet = null, fact = null, action = null;
		
		public void merge(DataFlowElementMap other) {
			if (line == null && other.line != null)
				this.line = other.line;
			if (lineText == null && other.lineText != null)
				this.lineText = other.lineText;
			if (column == null && other.column != null) 
				this.column = other.column;
			if (fileName == null && other.fileName != null) 
				this.fileName = other.fileName;
			if (node == null && other.node != null) 
				this.node = other.node;
			if (snippet == null && other.snippet != null) 
				this.snippet = other.snippet;
			if (fact == null && other.fact != null) 
				this.fact = other.fact;
			if (action == null && other.action != null) 
				this.action = other.action;

		}
	}

	@Override
	public String getType() {
		return ScannerType.FORTIFY.getFullName();
	}
}
