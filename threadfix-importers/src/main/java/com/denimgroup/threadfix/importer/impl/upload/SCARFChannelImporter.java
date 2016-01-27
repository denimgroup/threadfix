////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.CLANG_DB_NAME;
import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.SCARF_DB_NAME;

/**
 * 
 * @author stran
 */
@ScanImporter(
        scannerName = SCARF_DB_NAME,
        startingXMLTags = {"AnalyzerReport"}
)
public class SCARFChannelImporter extends AbstractChannelImporter {

	public static final String ROOT_NODE_NAME = "AnalyzerReport",
			BUG_INSTANCE = "BugInstance";

	private static final Map<String, String> toolNameMap = map("clang-sa", CLANG_DB_NAME);

	private static final String TOOL_NAME = "tool_name",
			BUG_LOCATIONS = "BugLocations",
			LOCATION = "Location",
			SOURCE_FILE = "SourceFile",
			START_LINE = "StartLine",
			END_LINE = "EndLine",
			START_COLUMN = "StartColumn",
			EXPLANATION = "Explanation",
			BUG_GROUP = "BugGroup",
			BUG_CODE = "BugCode",
			BUG_MESSAGE = "BugMessage";

	public SCARFChannelImporter() {
		super(ScannerType.SCARF);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new SCARFSAXParser());
	}
	
	public class SCARFSAXParser extends HandlerWithBuilder {
		Map<FindingKey, String> findingMap = map();

		String toolName = null;

		// These are per-BugInstance
		private StringBuffer currentRawFinding	  = new StringBuffer();
		String currentFileName = null,
				findingLineNumber = null,
				bugGroup = null,
				bugCode = null,
				bugMessage = null;

		// These are per-Location
		String lineNumber = null,
				columnNumber = null,
				fileName = null;

		boolean getText = false;
		int currentSequence = 1;
		boolean inFinding = false;
		boolean inPrimaryLocation = false;

		List<DataFlowElement> currentDataFlowElements = list();

		void addFinding() {

			findingMap.put(FindingKey.PATH, currentFileName);
			findingMap.put(FindingKey.PARAMETER, null);
			findingMap.put(FindingKey.VULN_CODE, bugGroup + ":" + bugCode);
			findingMap.put(FindingKey.SEVERITY_CODE, "Medium");
			findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

			Finding finding = constructFinding(findingMap);

			if (finding != null) {
				finding.setSourceFileLocation(currentFileName);

				finding.setEntryPointLineNumber(IntegerUtils.getPrimitive(findingLineNumber));
				finding.setLongDescription(bugMessage);
				finding.setNativeId(getNativeId(finding));
				finding.setIsStatic(true);
				finding.setDataFlowElements(currentDataFlowElements);
				saxFindingList.add(finding);
			}

			currentSequence = 1;
			currentFileName = null;
			findingLineNumber = null;
			currentDataFlowElements = list();
			inFinding = false;
			currentRawFinding.setLength(0);
			bugCode = bugGroup = bugMessage = null;
		}

		void addDataFlowElement() {
			DataFlowElement element = new DataFlowElement();
			element.setLineNumber(IntegerUtils.getPrimitive(lineNumber));
			element.setColumnNumber(IntegerUtils.getPrimitive(columnNumber));
			element.setSourceFileName(fileName);
			element.setSequence(currentSequence++); // ++ in use!
			currentDataFlowElements.add(element);
			fileName = lineNumber = columnNumber = null;
			inPrimaryLocation = false;
		}

		////////////////////////////////////////////////////////////////////
		// Event handlers.
		////////////////////////////////////////////////////////////////////

		public void startElement (String uri, String name,
								  String qName, Attributes atts) {

			// Since we're two lines shorter I think if/else works better here
			if (qName.equals(ROOT_NODE_NAME)) {
				toolName = atts.getValue(TOOL_NAME);
				if (toolNameMap.containsKey(toolName)){
					channelTypeCode = toolNameMap.get(toolName);
					channelType = channelTypeDao.retrieveByName(channelTypeCode);
				}

			} else if (qName.equals(BUG_INSTANCE)) {
				inFinding = true;

			} else if (qName.equals(LOCATION)) {
				inFinding = true;
				if ("true".equals(atts.getValue("primary"))) {
					inPrimaryLocation = true;
				}

			} else if (qName.equals(START_LINE) || qName.equals(START_COLUMN) || qName.equals(SOURCE_FILE)
					|| qName.equals(BUG_CODE) || qName.equals(BUG_MESSAGE) || qName.equals(BUG_GROUP)) {
				getText = true;
			}

			if (inFinding)
				currentRawFinding.append(makeTag(name, qName , atts));
		}

		public void endElement (String uri, String name, String qName) {
			if (getText) {
				if (qName.equals(START_LINE)) {
					lineNumber = getBuilderText();
					if (inPrimaryLocation)
						findingLineNumber = lineNumber;
				} else if (qName.equals(START_COLUMN)) {
					columnNumber = getBuilderText();
				} else if (qName.equals(SOURCE_FILE)) {
					fileName = getBuilderText();
					if (inPrimaryLocation)
						currentFileName = fileName;
				} else if (qName.equals(BUG_CODE)) {
					bugCode = getBuilderText();
				} else if (qName.equals(BUG_GROUP)) {
					bugGroup = getBuilderText();
				}else if (qName.equals(BUG_MESSAGE)) {
					bugMessage = getBuilderText();
				}
				getText = false;
			} else {
				if (qName.equals(LOCATION)) {
					addDataFlowElement();

				} else if (qName.equals(BUG_LOCATIONS)) {

				} else if (qName.equals(BUG_INSTANCE)) {
					currentRawFinding.append("</").append(qName).append(">");
					addFinding();
				}
			}
			if (inFinding){
				currentRawFinding.append("</").append(qName).append(">");
			}

		}

		public void characters (char[] ch, int start, int length) {
			if (getText) {
				addTextToBuilder(ch, start, length);
			}
			if (inFinding)
				currentRawFinding.append(ch,start,length);
		}
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new SCARFSAXValidator());
	}
	
	public class SCARFSAXValidator extends HandlerWithBuilder {
		private boolean correctFormat = false;

	    private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
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
			if (ROOT_NODE_NAME.equals(qName)) {
				correctFormat = true;
			}

	    	if (BUG_INSTANCE.equals(qName)) {
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
