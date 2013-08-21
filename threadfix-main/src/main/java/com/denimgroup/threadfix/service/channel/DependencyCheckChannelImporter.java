package com.denimgroup.threadfix.service.channel;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Dependency;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

public class DependencyCheckChannelImporter extends AbstractChannelImporter {
	
	private static Map<String, FindingKey> tagMap = new HashMap<>();
	static {
		tagMap.put("cwe", FindingKey.VULN_CODE);
		tagMap.put("severity", FindingKey.SEVERITY_CODE);
		tagMap.put("name", FindingKey.CVE);
	}

	@Autowired
	public DependencyCheckChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		setChannelType(ChannelType.MANUAL);
	}
	
	@Override
	@Transactional
	public Scan parseInput() {
		return parseSAXInput(new DependencyCheckSAXParser());
	}
	
	public class DependencyCheckSAXParser extends HandlerWithBuilder {
		
		private boolean getDate   = false;
		private boolean inFinding = false;
		
		private FindingKey itemKey = null;
	
		private Map<FindingKey, String> findingMap = null;
					    
	    public void add(Finding finding) {
			if (finding != null) {
//    			finding.setNativeId(getNativeId(finding));
    			finding.setNativeId(finding.getDependency().getCve());
	    		saxFindingList.add(finding);
    		}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("reportDate".equals(qName)) {
	    		getDate = true;
	    	} else if ("vulnerability".equals(qName)) {
	    		findingMap = new EnumMap<>(FindingKey.class);
	    		inFinding = true;
	    	} else if (inFinding && tagMap.containsKey(qName)) {
	    		itemKey = tagMap.get(qName);
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("vulnerability".equals(qName)) {
	    		updateVulnCode(findingMap);
	    		Finding finding = constructFinding(findingMap); 
	    		Dependency dependency = new Dependency();
	    		dependency.setCve(findingMap.get(FindingKey.CVE));
	    		finding.setDependency(dependency);
	    		add(finding);
	    		findingMap = null;
	    		inFinding = false;
	    	} else if (inFinding && itemKey != null) {
	    		String currentItem = getBuilderText();
	    		
	    		if (currentItem != null && findingMap.get(itemKey) == null) {
	    			findingMap.put(itemKey, currentItem);
	    		}
	    		itemKey = null;
	    	} 
	    	
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = getCalendarFromString("MMM dd, yyyy kk:mm:ss aa", tempDateString); 
	    		}
	    		getDate = false;
	    	} 
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || itemKey != null) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	    
	    private void updateVulnCode(Map<FindingKey, String> findingMap) {
	    	if (findingMap.get(FindingKey.VULN_CODE) == null) {
	    		findingMap.put(FindingKey.VULN_CODE, "Configuration");
	    	} else {
	    		String vulnCode = findingMap.get(FindingKey.VULN_CODE);
	    		if (vulnCode.startsWith("CWE")) {
	    			int i = vulnCode.indexOf(" ");
	    			if (i > 0) {
	    				findingMap.put(FindingKey.VULN_CODE, vulnCode.substring(i+1));
	    			}
	    		}
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new DependencyCheckSAXValidator());
	}
	public class DependencyCheckSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
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
	    	if ("analysis".equals(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if ("reportDate".equals(qName)) {
	    		getDate = true;
	    	}
	    	
	    	if ("vulnerability".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			testDate = getCalendarFromString("MMM dd, yyyy kk:mm:ss aa", tempDateString);
	    		}
	    		
	    		hasDate = testDate != null;
	    		getDate = false;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
}
