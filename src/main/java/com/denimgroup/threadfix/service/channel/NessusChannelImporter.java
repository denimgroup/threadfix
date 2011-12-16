////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * TODO import more scans and make sure parameters and paths 
 * are parsed correctly for all vuln types.
 * 
 * @author mcollins
 */
public class NessusChannelImporter extends AbstractChannelImporter {
	
	private static final String simpleHttpRegex = "(http[^\n]*)";
	private static final String urlColonRegex   = "URL  : ([^\n]*)\n";
	private static final String pageColonRegex  = "Page : ([^\n]*)\n";
	
	private static final String inputNameColonParamRegex = "Input name : ([^\n]*)\n";
	
	private static final Map<String,String> pathParseMap = new HashMap<String,String>();
	static {
		pathParseMap.put("26194", pageColonRegex);
		pathParseMap.put("11411", urlColonRegex);
		pathParseMap.put("40984", simpleHttpRegex);
	}
	
	private static final Map<String,String> paramParseMap = new HashMap<String,String>();
	static {
		paramParseMap.put("26194", inputNameColonParamRegex);
	}

	@Autowired
	public NessusChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.NESSUS);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new NessusSAXParser());
	}
	
	public class NessusSAXParser extends DefaultHandler {
		private Boolean getDate               = false;
		private Boolean getFindings           = false;
		private Boolean getNameText           = false;
		private Boolean getHost               = false;
	
		private String currentChannelVulnCode = null;
		private String currentSeverityCode    = null;
		private String host                   = null;
		
		private StringBuilder pluginOutputString = null;
		
		private String infoLineParamRegex = "\\+ The '([^&]+)' parameter of the [^ ]+ CGI :";
		private String infoLinePathRegex = "\\+ The '[^&]+' parameter of the ([^ ]+) CGI :";
					    
	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);
	    		saxFindingList.add(finding);
    		}
	    }
	    
	    //Once the entire string has been taken out of characters(), parse it
	    public void parseFindingString() {
	    	if (pluginOutputString == null)
	    		return;
	    	
	    	String stringResult = pluginOutputString.toString();
	    	if (stringResult == null || stringResult.trim().isEmpty())
	    		return;
	    	
	    	if (pathParseMap.containsKey(currentChannelVulnCode)) {
	    		parseRegexMatchesAndAdd(stringResult);
	    	} else {
	    		parseGenericPattern(stringResult);
	    	}
	    }

	    
	    private void parseRegexMatchesAndAdd(String stringResult) {
	    	String paramRegex = null,    pathRegex  = pathParseMap.get(currentChannelVulnCode);
    		Matcher paramMatcher = null, pathMatcher = Pattern.compile(pathRegex).matcher(stringResult);
    		
    		if (paramParseMap.containsKey(currentChannelVulnCode)) {
    			paramRegex = paramParseMap.get(currentChannelVulnCode);
    			paramMatcher = Pattern.compile(paramRegex).matcher(stringResult);
    		}
    		
    		int count = 1;
    		while (pathMatcher.find()) {
    			String param = null;
    			if (paramMatcher != null && paramMatcher.find(pathMatcher.start())) {
    				param = paramMatcher.group(1);
    			}
    				
    			
    			String path = pathMatcher.group(1);
    			
    			if (path != null && host != null && !path.startsWith("http"))
    				path = host + path;
    			
	    		Finding finding = constructFinding(path, param, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		add(finding);
	    		count++;
    		}
	    }
	    
	    private void parseGenericPattern(String stringResult) {
	    	String param, path;
	    	
	    	if (stringResult.contains("\n")) {
	    		String [] lines = stringResult.split("\n");
	    		
	    		for (String line : lines) {
	    			
	    			if (line == null || !line.contains("+ The '")) {
	    				continue;
	    			}
	    			
	    			param = getRegexResult(line,infoLineParamRegex);
	    			path = getRegexResult(line,infoLinePathRegex);
	    			
	    			if (path != null && host != null && !path.startsWith("http"))
	    				path = host + path;
	    			
	    			if (param != null || path != null) {
	    				Finding finding = constructFinding(path, param, 
	    	    				currentChannelVulnCode, currentSeverityCode);
	    	    		add(finding);
	    	    		param = null;
	    	    		path = null;
	    			}
	    		}
	    	}
	    }
	    
	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("ReportItem".equals(qName)) {
	    		currentChannelVulnCode = atts.getValue("pluginID");
	    		currentSeverityCode = atts.getValue("severity");
	    	} else if ("plugin_output".equals(qName)) {
	    		pluginOutputString = new StringBuilder();
	    		getFindings = true;
	    	} else if ("tag".equals(qName) && "HOST_END".equals(atts.getValue("name"))) {
	    		getDate = true;
	    	} else if (host == null && "name".equals(qName)) {
	    		getNameText = true;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("plugin_output".equals(qName)) {
	    		parseFindingString();
	    		pluginOutputString = null;
	    		getFindings = false;
	    		currentChannelVulnCode = null;
	    		currentSeverityCode = null;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);
	    		date = getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);
	    		getDate = false;
	    		
	    	} else if (getFindings) {
	    		char [] mychars = new char[length];
	    		System.arraycopy(ch, start, mychars, 0, length);
	    		pluginOutputString.append(mychars);
	    	} else if (getNameText) {
	    		String text = getText(ch,start,length);
	    		
	    		if ("TARGET".equals(text))
	    			getHost = true;
	    		getNameText = false;
	    	} else if (getHost) {
	    		String text = getText(ch,start,length);
	    		
	    		if (text != null && text.startsWith("http")) {
	    			host = text;
	    			if (host.charAt(host.length()-1) == '/') {
	    				host = host.substring(0,host.length()-1);
	    			}
	    			try {
						URL testUrl = new URL(host);
						host = testUrl.getProtocol() + "://" + testUrl.getHost();
					} catch (MalformedURLException e) {
						log.warn("Nessus parser tried to parse " + host + " as a URL.", e);
					}
	    			getHost = false;
	    		}
	    	}
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new NessusSAXValidator());
	}
	
	public class NessusSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
		private boolean clientDataTag = false;
		private boolean reportTag = false;
		
	    private void setTestStatus() {
	    	correctFormat = clientDataTag && reportTag;
	    	
	    	if (!correctFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((testStatus == null || SUCCESSFUL_SCAN.equals(testStatus)) && !hasFindings)
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
	    	if ("NessusClientData_v2".equals(qName)) {
	    		clientDataTag = true;
	    	} else if ("Report".equals(qName)) {
	    		reportTag = true;
	    	} else if ("ReportItem".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	} else if ("tag".equals(qName) && "HOST_END".equals(atts.getValue("name"))) {
	    		getDate = true;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);
	    		testDate = getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);
	    		
	    		hasDate = testDate != null;
	    		
	    		getDate = false;
	    	}
	    }
	}
}
