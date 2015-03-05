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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.io.InputStream;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Parses the SCA Fortify fpr output file.
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.FORTIFY_DB_NAME,
        format = ScanFormat.ZIP,
        zipItems = "audit.fvdl"
)
public class FortifyChannelImporter extends AbstractChannelImporter {
	
	public FortifyChannelImporter() {
		super(ScannerType.FORTIFY);
		doSAXExceptionCheck = false;
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

		FortifyAuditXmlParser timeParser = new FortifyAuditXmlParser();
		ScanUtils.readSAXInput(timeParser, FILE_CHECK_COMPLETED, auditXmlStream);
		Calendar auditXmlDate = timeParser.resultTime;

		applySuppressedInformation(timeParser, returnScan);

		if (auditXmlDate == null) {
            returnScan.setImportTime(date);
        } else {
            returnScan.setImportTime(auditXmlDate);
        }

		deleteZipFile();

		for (Map.Entry<String, Integer> stringIntegerEntry : resultMap.entrySet()) {
			System.out.println(stringIntegerEntry.getKey() + "," + stringIntegerEntry.getValue());
		}

		return returnScan;
	}

	Map<String, Integer> resultMap = newMap();

	private void applySuppressedInformation(FortifyAuditXmlParser timeParser, Scan returnScan) {
		Set<String> suppressedIds = timeParser.suppressedIds;

		for (Finding finding : returnScan) {
			if (suppressedIds.contains(finding.getNativeId())) {
				finding.setMarkedFalsePositive(true);
			}
		}
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
		
		List<Map<String,String>> rawFindingList = list();
		
		List<DataFlowElementMap> dataFlowElementMaps = list();
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
			dataFlowElementMaps = list();
			currentMap = null;
	    }
	    
	    public void expandFindings() {
	    	String nativeId = null;
	    	
	    	for (Map<String, String> findingMap : rawFindingList) {
	    		nativeId = findingMap.get("nativeId");
	    		
	    		List<DataFlowElementMap> dataFlowElementMaps = 
	    			nativeIdDataFlowElementsMap.get(nativeId);
	    		
	    		List<DataFlowElement> dataFlowElements = DataFlowElementParser.parseDataFlowElements(dataFlowElementMaps, this);
	    		
	    		StaticPathInformation staticPathInformation = staticPathInformationMap.get(nativeId);
	    		
	    		String severity = getSeverityName(getFloatOrNull(findingMap.get("confidence")),
	    				ruleMap.get(findingMap.get("classID")));
	    			    		
	    		if (severity == null) {
	    			severity = findingMap.get("severity");
	    		}
	   
	    		Finding finding = constructFinding(currentPath, currentParameter,
	    				findingMap.get("channelType"), severity);
                if (finding != null) {
                    finding.setNativeId(nativeId);
                    finding.setDataFlowElements(dataFlowElements);
                    finding.setIsStatic(true);
                    finding.setSourceFileLocation(currentPath);
                    finding.setStaticPathInformation(staticPathInformation);
                    saxFindingList.add(finding);
                }
                // re-initialize everything
	    		currentPath = null;
	    		currentParameter = null;
				currentChannelType = null;
				currentSeverity = null;
				nativeId = null;
	    	}
	    }

		/**
		 * This method generates the default confidence, pre-filtering by Fortify
		 */
	    private String getSeverityName(Float confidence, Map<String, Float> map) {
			String result;

			Float accuracy = map.get("Accuracy");
			Float probability = map.get("Probability");
			if (confidence != null && map.get("Impact") != null &&
					probability != null && accuracy != null)  {
				
				Float impact = map.get("Impact");

				Float likelihood = (float) (confidence * accuracy * probability) / 25;

				// TODO figure out what we should actually be doing here.
				// This comes from the Fortify javadoc and *almost* works with our sample files.

				if (impact >= 2.5F && likelihood >= 2.5F) {
					result = "Critical";
				} else if (impact >= 2.5F) {
					result = "High";
				} else if (likelihood >= 2.5F) {
					result = "Medium";
				} else {
					result = "Low";
				}

				String key = confidence + "," + accuracy + "," + probability + "," + impact + "," + likelihood + "," + result;

				if (!resultMap.containsKey(key)) {
					resultMap.put(key, 0);
				}

				resultMap.put(key, resultMap.get(key) + 1);

			} else {
				result = null;
			}
			return result;
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
		    		date = DateUtils.getCalendarFromString("yyyy-MM-dd hh:mm:ss", dateString);
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
					String groupName = atts.getValue("name");
					if (groupName.equals("Impact")) {
	    				 getImpact = true;
	    			 } else if (groupName.equals("Probability")) {
	    				 getProbability = true;
	    			 } else if (groupName.equals("Accuracy")) {
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
		    		if (split.length > 3) {
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
	    
	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
        try {
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
        } finally {
            deleteZipFile();
        }
	}

	public class FortifySAXValidator extends DefaultHandler {
		
		private boolean hasFindings = false;
		private boolean correctFormat = false;
		
		private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (testDate != null)
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

	    public void startElement (String uri, String name, String qName, Attributes atts) 
	    		throws SAXException {	    	
	    	if ("FVDL".equals(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if (testDate == null && "CreatedTS".equals(qName) 
	    			&& atts.getValue("date") != null
	    			&& atts.getValue("time") != null) {
	    		testDate = DateUtils.getCalendarFromString("yyyy-MM-dd hh:mm:ss",
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
		FortifyAuditXmlParser timeParser = new FortifyAuditXmlParser();
		ScanUtils.readSAXInput(timeParser, FILE_CHECK_COMPLETED, stream);

		return timeParser.resultTime;
	}

}
