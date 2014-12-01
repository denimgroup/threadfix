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
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.ResourceUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

@ScanImporter(
        scannerName = ScannerDatabaseNames.SSVL_DB_NAME,
        startingXMLTags = { "Vulnerabilities", "Vulnerability" }
)
public class SSVLChannelImporter extends AbstractChannelImporter {

	public final static String DATE_PATTERN = "MM/dd/yyyy hh:mm:ss a X";

	public SSVLChannelImporter() {
		super(ScannerType.MANUAL);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new SSVLChannelImporterSAXParser());
	}

	public class SSVLChannelImporterSAXParser extends HandlerWithBuilder {
		
		private boolean getText = false;
		private String description = null;

		private List<DataFlowElement> dataFlowElementList = list();
		private DataFlowElement lastDataFlowElement = null;
		
		private Map<FindingKey, String> findingMap = new HashMap<>();
					    
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
	    
	    @Override
		public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	switch (qName) {
	    		case "Vulnerabilities"    : parseDate(atts);            break;
	    		case "Vulnerability"      : parseTypeAndSeverity(atts); break;
	    		case "Finding"            : parseNativeId(atts);        break;
	    		case "SurfaceLocation"    : parseSurfaceLocation(atts); break;
	    		case "FindingDescription" : getText = true;             break;
	    	}
	    }
	    
	    private void parseDate(Attributes atts) {
	    	date = DateUtils.getCalendarFromString(DATE_PATTERN, atts.getValue("ExportTimestamp"));
	    }
	    
	    private void parseTypeAndSeverity(Attributes atts) {
	    	findingMap.put(FindingKey.VULN_CODE,     atts.getValue("CWE"));
	    	findingMap.put(FindingKey.SEVERITY_CODE, atts.getValue("Severity"));
	    }
	    
	    private void parseNativeId(Attributes atts) {
	    	findingMap.put(FindingKey.NATIVE_ID, atts.getValue("NativeID"));
	    }
	    
	    private void parseSurfaceLocation(Attributes atts) {
	    	findingMap.put(FindingKey.PARAMETER, atts.getValue("value"));
	    	findingMap.put(FindingKey.PATH,      atts.getValue("url"));
	    }
	    
	    @Override
		public void endElement (String uri, String name, String qName)
	    {
	    	switch (qName) {
	    		case "Finding"            : finalizeFinding();         break;
	    		case "LineText"           : addLineText();             break;
	    		case "DataFlowElement"    : finalizeDataFlowElement(); break;
	    		case "FindingDescription" : addDescription();          break;
	    	}
	    }

	    private void finalizeDataFlowElement() {
			if (lastDataFlowElement != null) {
				lastDataFlowElement.setLineText(getBuilderText());
				dataFlowElementList.add(lastDataFlowElement);
			}
		}

		private void addLineText() {
			if (lastDataFlowElement != null) {
				lastDataFlowElement.setLineText(getBuilderText());
			}
			
			getText = false;
		}
		
		private void addDescription() {
			description = getBuilderText();
			getText = false;
		}

		private void finalizeFinding() {
			String id = findingMap.get(FindingKey.VULN_CODE);
			
			// TODO also write support for vulns entered into the short description field.
			if (id != null && id.matches("[0-9]+")) {
				GenericVulnerability genericVulnerability =
						genericVulnerabilityDao.retrieveByDisplayId(Integer.valueOf(id));
				
				if (genericVulnerability != null && genericVulnerability.getName() != null) {
					findingMap.put(FindingKey.VULN_CODE, genericVulnerability.getName());
				}
			
				Finding finding = constructFinding(findingMap);
                if (finding != null) {
                    if (!dataFlowElementList.isEmpty()) {
                        finding.setIsStatic(true);
                        finding.setDataFlowElements(dataFlowElementList);
                        dataFlowElementList = list();
                    }
                    if (description != null) {
                        finding.setLongDescription(description);
                    }
                    add(finding);
                }
				findingMap = new HashMap<>();
				description = null;
			}
		}

		@Override
		public void characters (char ch[], int start, int length) {
	    	if (getText) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
	
	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		
		boolean valid = false;
		
		try {
			URL schemaFile = ResourceUtils.getResourceAsUrl("ssvl.xsd");

            if (schemaFile == null) {
                throw new IllegalStateException("ssvl.xsd file not available from ClassLoader. Fix that.");
            }

            if (inputFileName == null) {
                throw new IllegalStateException("inputFileName was null, unable to load scan file.");
            }

			Source xmlFile = new StreamSource(new File(inputFileName));
			SchemaFactory schemaFactory = SchemaFactory
			    .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = schemaFactory.newSchema(schemaFile);
			Validator validator = schema.newValidator();
		    validator.validate(xmlFile);
		    
		    valid = true;
		    
		    log.info(xmlFile.getSystemId() + " is valid");
		    
		} catch (MalformedURLException e) {
			log.error("Code contained an incorrect path to the XSD file.", e);
		} catch (SAXException e) {
			log.warn("SAX Exception encountered, ", e);
		} catch (IOException e) {
			log.warn("IOException encountered, ", e);
		}
		
		if (valid) {
			return testSAXInput(new SSVLChannelSAXValidator());
		} else {
			return new ScanCheckResultBean(ScanImportStatus.FAILED_XSD);
		}
	}
	
	public class SSVLChannelSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasVulnerabilitiesTag = false;
		
	    private void setTestStatus() {
	    	if (!(hasVulnerabilitiesTag && hasFindings)) {
				testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
			} else if (testDate != null) {
				testStatus = checkTestDate();
			}
	    	
	    	if (testStatus == null) {
				testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
			}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    @Override
		public void endDocument() {
	    	setTestStatus();
	    }

	    @Override
		public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	switch (qName) {
	    		case "Vulnerabilities" : parseDate(atts);    break;
	    		case "Vulnerability"   : hasFindings = true; break;
	    	}
	    }
	    
	    private void parseDate(Attributes atts) {
	    	hasVulnerabilitiesTag = true;
	    	testDate = DateUtils.getCalendarFromString(DATE_PATTERN, atts.getValue("ExportTimestamp"));
	    }
	}
}
