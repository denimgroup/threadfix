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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * Imports the results of a W3AF scan (xml output).
 * 
 * The only information tags it currently handles are the "Interesting file" ones.
 * 
 * @author mcollins
 */
public class W3afChannelImporter extends AbstractChannelImporter {
	
	public static final String POTENTIALLY_INTERESTING_FILE = "Potentially interesting file";
	
	/**
	 * Constructor with Spring dependencies injected.
	 * 
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public W3afChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;

		setChannelType(ChannelType.W3AF);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		
		try {
			removeTagFromInputStream("httpresponse");
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return parseSAXInput(new W3afSAXParser());
	}
	
	/*
	 * This method takes the name of a tag as a parameter and then replaces the inputStream object 
	 * with a new InputStream that does not include any of those tags.
	 * 
	 *  The start tag must start with the text <tagName and the end tag must be </tagName>.
	 *  
	 *  This method could be adapted to take out any of a list of tags and is fairly generic.
	 * 
	 * @param tagName
	 * @throws IOException
	 */
	private void removeTagFromInputStream(String tagName) throws IOException {
		if (inputStream == null)
			 return;
		
		String startTag = "<" + tagName, endTag = "</" + tagName + ">";
		 
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		StringBuilder contents = new StringBuilder();
		 
		String inputValue = reader.readLine();
		 
		boolean inResponseTag = false;
		
		while (inputValue != null) {
			
			if (inputValue.contains(startTag)) {
				if (inputValue.contains(endTag)) {
					inputValue = inputValue.substring(0,inputValue.indexOf(startTag)) +
									inputValue.substring(inputValue.indexOf(endTag) + endTag.length());
				} else {
					inResponseTag = true;
					inputValue = inputValue.substring(0,inputValue.indexOf(startTag));
					contents.append(inputValue);
				}
			}
			
			if (inResponseTag && inputValue.contains(endTag)) {
				inResponseTag = false;
				inputValue = inputValue.substring(inputValue.indexOf(endTag) + endTag.length());
			}
			
			if (!inResponseTag) {
				contents.append(inputValue);
			}
			
			inputValue = reader.readLine();
		}
		
		inputStream = new ByteArrayInputStream(contents.toString().getBytes("UTF-8"));
	}

	public class W3afSAXParser extends DefaultHandler {

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

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("w3afrun".equals(qName))
	    		date = getCalendarFromString("EEE MMM dd HH:mm:ss yyyy", atts.getValue("startstr"));
	    		    	
	    	if ("vulnerability".equals(qName) && atts.getValue("url") != null && 
	    			!atts.getValue("url").isEmpty()) {
	    		
	    		String param = atts.getValue("var");
	    		if ("None".equals(param)) 
	    			param = null;
	    		
	    		Finding finding = constructFinding(atts.getValue("url"),
	    										   param,
	    										   atts.getValue("name"),
	    										   atts.getValue("severity"));
	    		add(finding);
	    	}
	    	
	    	if ("information".equals(qName) && POTENTIALLY_INTERESTING_FILE.equals(atts.getValue("name")) &&
	    			atts.getValue("url") != null && !atts.getValue("url").isEmpty()) {
	    		Finding finding = constructFinding(atts.getValue("url"),
												   null,
												   atts.getValue("name"),
												   "Info");
	    		
				add(finding);
	    	}
	    }
	}

	@Override
	public String checkFile() {
		
		try {
			removeTagFromInputStream("httpresponse");
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return testSAXInput(new W3afSAXValidator());
	}
	
	public class W3afSAXValidator extends DefaultHandler {
		private boolean hasFindings = false, hasDate = false, correctFormat = false;
	    
	    private void setTestStatus() {
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

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("vulnerability".equals(qName))
	    		hasFindings = true;
	    	
	    	if (!correctFormat && "w3afrun".equals(qName)) {
	    		correctFormat = true;
	    		testDate = getCalendarFromString("EEE MMM dd HH:mm:ss yyyy", atts.getValue("startstr"));
	    		hasDate = testDate != null;
	    	}
	    }
	}
}
