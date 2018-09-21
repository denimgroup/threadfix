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
import com.denimgroup.threadfix.importer.impl.upload.WebInspectChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.InputStream;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;

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

	FortifyFilterSet filterSet = new FortifyFilterSet();
	Set<String> filteredHiddenIds = set();

	@Override
	@Transactional
	public Scan parseInput() {
		zipFile = unpackZipStream();

		InputStream auditXmlStream   = getFileFromZip("audit.xml");
		InputStream fvdlInputStream  = getFileFromZip("audit.fvdl");
		InputStream filterStream     = getFileFromZip("filtertemplate.xml");
		InputStream webinspectStream = getFileFromZip("WEBINSPECT.xml");

		if (zipFile == null || fvdlInputStream == null)
			return null;

		if (filterStream != null) {
			inputStream = filterStream;
			FilterTemplateXmlParser parser = new FilterTemplateXmlParser();
			parseSAXInput(parser);
			filterSet = parser.filterSet;
		}

		Scan webinspectScan = null;
		if (webinspectStream != null) {
			WebInspectChannelImporter importer = new WebInspectChannelImporter();

			// TODO refactor unit tests to avoid this code
			// it doesn't hurt anything; just ugly
			importer.channelSeverityDao = this.channelSeverityDao;
			importer.channelVulnerabilityDao = this.channelVulnerabilityDao;
			importer.genericVulnerabilityDao = this.genericVulnerabilityDao;
			importer.channelTypeDao = this.channelTypeDao;

			importer.setInputStream(webinspectStream);

			webinspectScan = importer.parseInput();

			reassignSeverities(webinspectScan);
		}

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

		if (webinspectScan != null) {
			returnScan.getFindings().addAll(webinspectScan.getFindings());
		}

		return returnScan;
	}

	/**
	 * WebInspect scans are subject to Fortify's filtering rules too, but under a different system.
	 *
	 * WebInspect 4 -> impact 5, likelihood 5.
	 * WebInspect 3 -> impact 3, likelihood 2.
	 * WebInspect 2 -> impact 2, likelihood 3.
	 * WebInspect 1 -> impact 1, likelihood 1.
	 *
	 * We need to run these through the filter system, because user-defined filters
	 * can reassign any of these to any other category.
	 *
	 * @param webinspectScan WebInspect scan with raw severities
	 */
	private void reassignSeverities(Scan webinspectScan) {
		ChannelType type = channelTypeDao.retrieveByName(ScannerType.WEBINSPECT.getDbName());

		if (type == null) {
			throw new IllegalStateException("WebInspect channel type not found, can't continue.");
		}

		for (Finding finding : webinspectScan) {

			if (finding.getChannelSeverity() != null) {
				final float impact, likelihood;

				if (finding.getChannelSeverity().getName().equals("4")) {
					impact = 5f;
					likelihood = 5f;
				} else if (finding.getChannelSeverity().getName().equals("3")) {
					impact = 3f;
					likelihood = 2f;
				} else if (finding.getChannelSeverity().getName().equals("2")) {
					impact = 2f;
					likelihood = 3f;
				} else {
					impact = 1f;
					likelihood = 1f;
				}

				Map<String, Float> map = map("Impact", impact, "Likelihood", likelihood);

				// it's ok for the map to be empty for now
				String result = filterSet.getResult(new HashMap<VulnKey, String>(), map);

				if (result != null) {
					ChannelSeverity newSeverity = channelSeverityDao.retrieveByCode(type, severityMap.get(result));
					finding.setChannelSeverity(newSeverity);
				}
			}
		}
	}

	private static final Map<String, String> severityMap = map(
			"Critical", "4",
			"Hot", "4",
			"High", "3",
			"Warning", "3",
			"Medium", "2",
			"Low", "1"
	);

	private void applySuppressedInformation(FortifyAuditXmlParser timeParser, Scan returnScan) {
		Set<String> suppressedIds = timeParser.suppressedIds;

		for (Finding finding : returnScan) {
			if (suppressedIds.contains(finding.getNativeId()) ||
					filteredHiddenIds.contains(finding.getNativeId())) {
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
		Map<String, List<DataFlowElementMap>> nativeIdDataFlowElementsMap = map();
		Map<String, StaticPathInformation> staticPathInformationMap = map();
		
		List<Map<String,String>> rawFindingList = list();
		
		List<DataFlowElementMap> dataFlowElementMaps = list();
		DataFlowElementMap currentMap = null;
		StaticPathInformation currentStaticPathInformation = null;
		
		Map<String, DataFlowElementMap> nodeSnippetMap = map();
		
		Map<String, Map<String, Float>> ruleMap = map();
		String currentRuleID = null;

		String currentKingdom = null;
		String currentCategory = null;
		String currentChannelType = null;
		String currentChannelSubtype = null;
		String currentSeverity = null;
		String currentNativeId = null;
		String currentPath = null;
		String currentParameter = null;
		String currentConfidence = null;
		String currentClassID = null;
		String currentTaint = null;
		
		String nodeId = null;
		
		Map<String, String> snippetMap = map();
		String snippetId = null;
		int lineCount = 0;
		boolean getSnippetText = false;

		boolean getTaint = false;
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
		boolean getKingdom = false;
		
		boolean skipToNextVuln = false;
		boolean doneWithVulnerabilities = false;
		
	    public void addToList() {
	    	Map<String,String> findingMap = map();
	    	
	    	if (currentChannelType != null && currentChannelSubtype != null && 
	    			!currentChannelSubtype.trim().equals("")) {
	    		currentChannelType = currentChannelType + ": " + currentChannelSubtype;
	    	}

	    	findingMap.put("channelType", currentChannelType);
	    	findingMap.put("severity",currentSeverity);
	    	findingMap.put("nativeId", currentNativeId);
	    	findingMap.put("confidence", currentConfidence);
	    	findingMap.put("classID", currentClassID);
			findingMap.put("Kingdom", currentKingdom);
			findingMap.put("Category", currentCategory);
			findingMap.put("Taint", currentTaint);
	    	staticPathInformationMap.put(currentNativeId, currentStaticPathInformation);
	    	nativeIdDataFlowElementsMap.put(currentNativeId, dataFlowElementMaps);
	    	
	    	rawFindingList.add(findingMap);
	    	
			currentKingdom = null;
	    	currentChannelType = null;
			currentTaint = null;
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
	    	String nativeId;
	    	
	    	for (Map<String, String> findingMap : rawFindingList) {
	    		nativeId = findingMap.get("nativeId");
	    		
	    		List<DataFlowElementMap> dataFlowElementMaps = 
	    			nativeIdDataFlowElementsMap.get(nativeId);
	    		
	    		List<DataFlowElement> dataFlowElements = DataFlowElementParser.parseDataFlowElements(dataFlowElementMaps, this);
	    		
	    		StaticPathInformation staticPathInformation = staticPathInformationMap.get(nativeId);

				Float confidence = getFloatOrNull(findingMap.get("confidence"));
				Map<String, Float> numberMap = ruleMap.get(findingMap.get("classID"));
				Float likelihood = getLikelihood(confidence, numberMap);
				Float impact = numberMap.get("Impact");
				numberMap.put("Likelihood", likelihood);

				String severity = findingMap.get("severity");

				if (likelihood > 0f) {
					severity = getSeverityName(
							impact,
							likelihood);
				} else {
					numberMap.put("Severity", getFloatOrNull(severity));
				}

				numberMap.put("Confidence", confidence);

				// TODO add analysis
				Map<VulnKey, String> vulnMap = map(
						VulnKey.FULL_CATEGORY, findingMap.get("channelType"),
						VulnKey.CATEGORY, findingMap.get("Category"),
						VulnKey.KINGDOM, findingMap.get("Kingdom"),
						VulnKey.TAINT, findingMap.get("Taint")
				);
	   			String filterSeverity = filterSet.getResult(vulnMap, numberMap);

				if (FortifyFilter.HIDE.equals(filterSeverity)) {
					filteredHiddenIds.add(findingMap.get("nativeId"));
				} else if (filterSeverity != null) {
					severity = filterSeverity;
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
	    	}
	    }

		/**
		 * @return likelihood calculated from the Fortify Javadoc formula
		 */
		private Float getLikelihood(Float confidence, Map<String, Float> map) {

			Float accuracy = map.get("Accuracy");
			Float probability = map.get("Probability");
			if (confidence != null &&
					probability != null && accuracy != null) {
				return confidence * accuracy * probability / 25;
			} else {
				return 0F;
			}
		}

		/**
		 * This method generates the default severity, pre-filtering by Fortify
		 */
		@Nonnull
	    private String getSeverityName(@Nonnull Float impact, @Nonnull Float likelihood) {
			final String result;

			if (impact >= 2.5F && likelihood >= 2.5F) {
				result = "Critical";
			} else if (impact >= 2.5F) {
				result = "High";
			} else if (likelihood >= 2.5F) {
				result = "Medium";
			} else {
				result = "Low";
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
		    	if ("Kingdom".equals(qName)) {
		    		skipToNextVuln = false;
		    		getKingdom = true;
		    	} else if ("Type".equals(qName)) {
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
				} else if ("Fact".equals(qName) && "TaintFlags".equals(atts.getValue("type"))){
		    		getTaint = true;
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
	    	if (getKingdom) {
				currentKingdom = getBuilderText();
				getKingdom = false;
			} else if (getChannelType) {
	    		currentChannelType = getBuilderText();
				currentCategory = currentChannelType;
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
			} else if (getTaint) {
				currentTaint = getBuilderText();
				getTaint = false;
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
	    			getProbability || getAccuracy || getConfidence || getStaticPathInformationUrl
					|| getKingdom || getTaint) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

	@Nullable
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
