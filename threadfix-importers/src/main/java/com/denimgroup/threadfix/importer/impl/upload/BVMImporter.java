package com.denimgroup.threadfix.importer.impl.upload;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;

import org.xml.sax.Attributes;

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.RegexUtils;

/**
 * author: dsavelski, Barracuda Networks
 */
@ScanImporter(
        // must match value in bnvlm.csv
        scannerName = ScannerDatabaseNames.BARRACUDA_BVM_DB_NAME,
        format = ScanFormat.XML,
        startingXMLTags = { "va-engine-result" }
)
public class BVMImporter extends AbstractChannelImporter {

    public BVMImporter() {
        super(ScannerType.BARRACUDA_BVM);
    }

    @Override
    public Scan parseInput() {
        return parseSAXInput(new BVMScanSAXParser());
    }

    public class BVMScanSAXParser extends HandlerWithBuilder {

        private FindingKey currentKey = null;
        private Map<FindingKey, String> findingMap = new HashMap<FindingKey, String>();
        private Map<String, String> recommendationsMap = new HashMap<String, String>();
        private String currentRecommendationId = null;
        
        private boolean inIssue = false;
        private boolean inVariants = false;
        private StringBuffer currentRawFinding = new StringBuffer();
        
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
        public void startElement(String uri, String name,
                                 String qName, Attributes atts) {
        	
        	if ("recommendation".equalsIgnoreCase(qName))
        		currentRecommendationId = atts.getValue("id");
        	
        	if ("issue".equalsIgnoreCase(qName)) {
        		inIssue = true;
        		
        		findingMap = new HashMap<FindingKey, String>();
        		findingMap.put(FindingKey.VULN_CODE, atts.getValue("IssueName"));
        		findingMap.put(FindingKey.DETAIL, atts.getValue("IssueName"));
        		findingMap.put(FindingKey.SEVERITY_CODE, atts.getValue("severity"));
        	}
        	
        	if ("variants".equalsIgnoreCase(qName))
        			inVariants = true;
        	
        	if (inIssue)
                currentRawFinding.append(makeTag(name, qName , atts));
        	
        	if ("url".equals(qName)){
        		currentKey = FindingKey.PATH;
        	} else if ("cve".equals(qName)){
        		currentKey = FindingKey.CVE;
        	} else if ("cwe".equals(qName)){
        		currentKey = FindingKey.CWE;
        	} else if ("confidence".equals(qName)){
        		currentKey = FindingKey.CONFIDENCE_RATING;
        	} else if ("recommendationId".equals(qName)){
            	currentKey = FindingKey.RECOMMENDATION;
        	} else if ("entity_name".equals(qName)){
        		currentKey = FindingKey.PARAMETER;
        	} else if (inVariants && "description".equals(qName)){
        		currentKey = FindingKey.DETAIL;
        	} else if (inVariants && "attackVector".equals(qName)){
        		currentKey = FindingKey.ATTACK_STRING;
        	}

        }

        @Override
        public void endElement(String uri, String name, String qName) {
        	if ("variants".equalsIgnoreCase(qName))
    			inVariants = false;
        	
        	if (inIssue)
                currentRawFinding.append("</").append(qName).append(">");
        	
        	if ("recommendation".equalsIgnoreCase(qName)) {
        		String rec_text = getBuilderText();
        		recommendationsMap.put(currentRecommendationId, rec_text);
        		currentRecommendationId = null;
        	}
        	
            if ("issue".equalsIgnoreCase(qName)) {
            	inIssue = false;

            	findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
            	currentRawFinding.setLength(0);
            	
            	Finding finding = constructFinding(findingMap);
                add(finding);
                
            } else if (currentKey != null) {
                // getBuilderText retrieves the text from the builder.
                // this should contain any text in the tag associated with the key
            	
            	String tmpBuilderText = getBuilderText();
            	
            	if (currentKey == FindingKey.CWE) {
            			tmpBuilderText = RegexUtils.getRegexResult(tmpBuilderText, "^CWE-([0-9]+)$");
            			findingMap.put(FindingKey.CWE, tmpBuilderText);	//
            	}
            	
            	if (currentKey == FindingKey.RECOMMENDATION) {
            		String recommendation = recommendationsMap.get(tmpBuilderText);
            		if (! "".equals(recommendation))
            			tmpBuilderText = recommendation;
            	}
            	
            	findingMap.put(currentKey, tmpBuilderText);
            	currentKey = null;
            }
        }

        @Override
        public void characters (char ch[], int start, int length) {
        	// if we're in an element that we should record, add the text between tags to the builder
        	
        	if (currentKey != null || currentRecommendationId != null) 
                addTextToBuilder(ch, start, length);
        	
        	if (inIssue)
        		currentRawFinding.append(ch,start,length);
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {

        // Do checks to determine the correct ScanImportStatus to return
        // this is where duplicate scan checking happens
        // the Calendar should be the scan date

        return new ScanCheckResultBean(ScanImportStatus.SUCCESSFUL_SCAN, Calendar.getInstance());
    }


}
