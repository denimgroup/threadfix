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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipFile;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.apache.commons.io.IOUtils;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * Parses the Skipfish output file. The zip upload will go look at the relevant request.dat file and try to
 * parse the correct parameter out, but relies on the fact that the Skipfish
 * payload is this string: -->">'>'"< in order to grab the variable names.
 * 
 * @author mcollins
 * 
 */
@PluginImplementation
public class SkipfishChannelImporter extends AbstractChannelImporter {

	private String folderName;
	
	// TODO use a different method to grab parameters. 
	// This one attempts to parse based on a limited set of payloads.
	private static final String [] SKIPFISH_PAYLOADS = { "--\\x3e\\x22\\x3e\\x27\\x3e\\x27\\x22", 
														"\\x3e\\x27\\x3e\\x22\\x3e\\x3",
														"./",
														".\\",
														"'\"",
														"\\x27\\x22",
														"-->\">'>'\"<",
														"%3B%3F"};
	
	private static final String [] SKIPFISH_PAYLOAD_REGEXES = { "--\\\\x3e\\\\x22\\\\x3e\\\\x27\\\\x3e\\\\x27\\\\x22", 
																"\\\\x3e\\\\x27\\\\x3e\\\\x22\\\\x3e\\\\x3",
																"\\.",
																"\\.",
																"'\"",
																"\\\\x27\\\\x22",
																"-->\\\">'>'\\\"<",
																"%3B%3F"};
	
	private static final String REGEX_START = "[\\?\\&]([0-9a-zA-Z_\\-]+)=[^\\&]+";
	
	private static final String INTERESTING_FILE_CODE = "40401";
	private static final String DIRECTORY_LISTING = "Directory listing";
	
	private Calendar date;
		
	public SkipfishChannelImporter() {
		super(ScannerType.SKIPFISH.getFullName());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		InputStream samplesFileStream = getSampleFileInputStream();
		
		List<?> map = getArrayFromSamplesFile(samplesFileStream);
		
		try {
			samplesFileStream.close();
		} catch (IOException e) {
			log.warn("The Skipfish samples.js fileStream wouldn't close.", e);
		}
		
		if (map == null)
			return null;
		
		List<Finding> findings = getFindingsFromMap(map);

		Scan scan = new Scan();
		scan.setFindings(findings);

		scan.setApplicationChannel(applicationChannel);
		scan.setImportTime(date);

		
		deleteZipFile();
		deleteScanFile();

		return scan;
	}
	
	private InputStream getSampleFileInputStream() {
		if (inputStream == null)
			return null;
		
		zipFile = unpackZipStream();
		if (zipFile == null)
			return null;
		
		folderName = findFolderName(zipFile);
		InputStream samplesFileStream;

		if (folderName != null)
			samplesFileStream = getFileFromZip(folderName + "/samples.js");
		else
			samplesFileStream = getFileFromZip("samples.js");

		return samplesFileStream;	
	}

	// This method parses the examples.js file into a Java object using a JSON parser.
	private List<?> getArrayFromSamplesFile(
			InputStream sampleFileInputStream) {
		if (sampleFileInputStream == null)
			return null;

		BufferedReader reader = new BufferedReader(new InputStreamReader(
				new DataInputStream(sampleFileInputStream)));

		String issuesString = "[";
		String tempString;
		boolean write = false;
		try {
			StringBuffer buffer = new StringBuffer();
			while ((tempString = reader.readLine()) != null) {
				if (write)
					buffer.append(tempString.replace("'",
							"\"").replace("\\", "\\\\"));
				else if (tempString.contains("var issue_samples"))
					write = true;
			}
			issuesString += buffer;
		} catch (IOException e) {
			e.printStackTrace();
		}

		List<?> result = null;

		ObjectMapper mapper = new ObjectMapper();
		try {
			Object value =  mapper.readValue(issuesString, ArrayList.class);
			
			if (value != null)
				result = (ArrayList<?>) value;
				
			reader.close();
			
		} catch (IOException e1) {
			e1.printStackTrace();
		}

        return result;
	}

	// For each category, find the channel vuln and severity and pass the other work off to another method.
	private List<Finding> getFindingsFromMap(List<?> map) {
		if (map == null)
			return null;

		List<Finding> findings = new ArrayList<>();

		for (Object mapElement : map) {
			if (mapElement instanceof HashMap<?, ?>) {
				Map<?, ?> mapElementHash = (HashMap<?,?>) mapElement;
				
				Object samples = mapElementHash.get("samples");
				if (samples == null || !(samples instanceof ArrayList<?>))
					continue;
				
				ChannelSeverity cs = null;
				ChannelVulnerability cv = null;
	
				if (mapElementHash.get("severity") != null && mapElementHash.get("severity").toString() != null)
					cs = getChannelSeverity(mapElementHash.get("severity").toString());
				if (mapElementHash.get("type") != null && mapElementHash.get("type").toString() != null)
					cv = getChannelVulnerability(mapElementHash.get("type").toString());
	
				List<Finding> tempList = getFindingsForSingleVuln(cs, cv,
						(ArrayList<?>) samples);
	
				if (tempList != null && tempList.size() != 0)
					findings.addAll(tempList);
			}
		}

		return findings;
	}

	// For each channel vuln and severity, parse each path / parameter combination into a finding.
	private List<Finding> getFindingsForSingleVuln(ChannelSeverity channelSeverity,
			ChannelVulnerability channelVulnerability, List<?> samples) {
		if (samples == null || samples.size() == 0)
			return null;

		List<Finding> returnList = new ArrayList<>();

		for (Object sample : samples) {
			if (sample == null || !(sample instanceof LinkedHashMap))
				continue;

			Map<?, ?> findingMap = (HashMap<?, ?>) sample;
			Finding finding = new Finding();
			finding.setIsStatic(false);
			finding.setChannelSeverity(channelSeverity);
			
			if (channelVulnerability != null && channelVulnerability.getCode() != null && channelVulnerability.getCode().equals(INTERESTING_FILE_CODE)) {
				Object extra = findingMap.get("extra");
				if (extra != null && extra instanceof String && 
						extra.equals(DIRECTORY_LISTING)) {
					ChannelVulnerability temp = getChannelVulnerability(INTERESTING_FILE_CODE + " " + DIRECTORY_LISTING);
					if (temp != null)
						finding.setChannelVulnerability(temp);
				}
			}
			
			if (finding.getChannelVulnerability() == null)
				finding.setChannelVulnerability(channelVulnerability);
			
			finding.setSurfaceLocation(new SurfaceLocation());

			String path = null, param = null, channelVulnName = null;

			Object url = findingMap.get("url");
			if (url != null && url instanceof String) {
				Object extraObject = findingMap.get("extra");
				
				if (extraObject != null && extraObject instanceof String) {
					if (((String) extraObject).startsWith("response suggests arithmetic evaluation on server side")) {
						if (((String) url).contains("-") && ((String) url).contains("?"))
							param = getRegexResult((String) url, REGEX_START + "-");
					}
				}
				
				if (((String) url).contains("?")) {
					for (int index = 0; index < SKIPFISH_PAYLOADS.length; index ++) {
						// If it has the payload, find the correct parameter and save it.
						if (param == null && ((String) url).contains(SKIPFISH_PAYLOADS[index]))
							param = getRegexResult((String) url, REGEX_START + SKIPFISH_PAYLOAD_REGEXES[index]);
					}
					path = ((String) url).substring(0, ((String) url).indexOf('?'));
				} else if (zipFile != null && param == null)
					param = attemptToParseParamFromHTMLRequest(findingMap);

				if (path == null)
					path = (String) url;
                for (String SKIPFISH_PAYLOAD : SKIPFISH_PAYLOADS)
                    if (path.contains(SKIPFISH_PAYLOAD))
                        path = path.substring(0, path.indexOf(SKIPFISH_PAYLOAD));
				
				finding.getSurfaceLocation().setParameter(param);
				
				Object requestLocation = findingMap.get("dir");
				String host = null;
				
				if (requestLocation != null && requestLocation.getClass().equals(String.class))
					host = attemptToParseHostFromHTMLRequest((String) requestLocation);
									
				if (host != null && path.contains(host)) {
					finding.getSurfaceLocation().setHost(host);
					finding.getSurfaceLocation().setPath(path.substring(path.indexOf(host) + host.length()));
    			} else {
    				finding.getSurfaceLocation().setPath(path);
    			}
									
				finding.getSurfaceLocation().setHost(host);
			}

			if (channelVulnerability != null && channelVulnerability.getName() != null)
				channelVulnName = channelVulnerability.getName();

			finding.setNativeId(hashFindingInfo(channelVulnName, path, param));

			returnList.add(finding);
		}

		return returnList;
	}

	// This is the method that tries to grab the parameter name out of the request.dat file.
	// It only works if the parameter is on the bottom line in a list, which it sometimes is.
	// Most parameters should be parsed before this method.
	private String attemptToParseParamFromHTMLRequest(Map<?, ?> findingMap) {
		if (findingMap == null || zipFile == null)
			return null;

		// First we need to get the file from the correct directory.
		InputStream requestInputStream = null;
		Object dir = findingMap.get("dir");
		if (dir != null && (dir instanceof String)) {
			if (folderName != null)
				requestInputStream = getFileFromZip(folderName + "/" + dir.toString() + "/request.dat");
			else
				requestInputStream = getFileFromZip(dir.toString() + "/request.dat");
			
			if (date == null)
				attemptToParseDate(dir.toString());
		}
		if (requestInputStream == null)
			return null;

		// Then we need to grab the last line with text and look for the XSS vuln code in it (-->">'>'"<)
		// It might be good to replace this with a regular expression but it would get complicated and this works.
		String requestString = getStringFromInputStream(requestInputStream);
		
		try {
			requestInputStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if (requestString == null)
			return null;
		
		if (requestString.contains("\n"))
			requestString = requestString.substring(requestString.lastIndexOf('\n') + 1);

		if (requestString.trim().equals(""))
			return null;
		
		boolean parseFlag = false;
		
		for (String payload : SKIPFISH_PAYLOADS) {
			if (requestString.contains(payload)) {
				requestString = requestString.substring(0, requestString.indexOf(payload));
				parseFlag = true;
				break;
			}
		}
		
		Object extraObject = findingMap.get("extra");
		
		if (extraObject != null && extraObject instanceof String) {
			if (((String) extraObject).startsWith("response suggests arithmetic evaluation on server side")) {
				requestString = requestString.substring(0, requestString.indexOf("-"));
				parseFlag = true;
			}
		}
		
		if (parseFlag && requestString.contains("=")) {
			requestString = requestString.substring(0, requestString.lastIndexOf('='));
			if (requestString.contains("&"))
				return requestString.substring(requestString.lastIndexOf('&') + 1);
			else
				return requestString;
		}

		return null;
	}
	
	private Calendar attemptToParseDate(String responseDataAddress) {
		if (zipFile == null)
			return null;
		
		InputStream requestInputStream = getFileFromZip(folderName + "/" + responseDataAddress + "/response.dat");
		if (requestInputStream == null) 
			return null;
		
		String responseString = getStringFromInputStream(requestInputStream);
		if (responseString == null) 
			return null;
		
		try {
			requestInputStream.close();
		} catch (IOException e) {
			log.warn("Closing an inputStream failed in attemptToParseDate() in SkipfishChannelImporter.", e);
		}
		
		date = attemptToParseDateFromHTTPResponse(responseString);
		return date;
	}
	
	private String attemptToParseHostFromHTMLRequest(String requestDataAddress) {
		if (zipFile == null)
			return null;

		// First we need to get the file from the correct directory.
		InputStream requestInputStream = getFileFromZip(folderName + "/" + requestDataAddress + "/request.dat");
		if (requestInputStream == null) return null;
		
		String requestString = getStringFromInputStream(requestInputStream);
		if (requestString == null) return null;
		
		try {
			requestInputStream.close();
		} catch (IOException e) {
			log.warn("Closing an inputStream failed in attemptToParseHostFromHTMLRequest() in SkipfishChannelImporter.", e);
		}
		
		return getRegexResult(requestString, "Host: ([^\\n\\r]+)");
	}
	
	private String getStringFromInputStream(InputStream stream) {
		Writer writer = new StringWriter();
		String returnValue = null;
		
		try {
			IOUtils.copy(stream, writer, "UTF-8");
			returnValue = writer.toString();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			closeInputStream(stream);
		}
		
		return returnValue;
	}

	// This method looks to see if the zip file contains the folder containing everything,
	// and returns the name of the folder so that paths can be correctly constructed.
	private String findFolderName(ZipFile zipFile) {
		if (zipFile == null)
			return null;

		if (zipFile.entries() != null && zipFile.entries().hasMoreElements()) {
			String possibleMatch = zipFile.entries().nextElement().toString();
			if (possibleMatch.charAt(0) != '_' && possibleMatch.contains("/"))
				return possibleMatch.substring(0, possibleMatch.indexOf("/"));
		}

		return null;
	}

	@Override
	public ScanCheckResultBean checkFile() {
		ScanImportStatus returnValue = null;
		
		InputStream sampleFileInputStream = getSampleFileInputStream();
		
		if (sampleFileInputStream == null)
			return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);
		
		List<?> map = getArrayFromSamplesFile(sampleFileInputStream);
		
		if (map == null)
			returnValue = ScanImportStatus.WRONG_FORMAT_ERROR;
		
		if (returnValue == null && map.size() == 0)
			returnValue = ScanImportStatus.EMPTY_SCAN_ERROR;
		
		if (returnValue == null) {
			checkMap(map);
	
	    	if (testDate != null)
	    		returnValue = checkTestDate();
		}
		
    	try {
			sampleFileInputStream.close();
		} catch (IOException e) {
			log.warn("Closing an inputStream failed in checkFile() in SkipfishChannelImporter.", e);
		}
		
		if (returnValue == null)
			returnValue = ScanImportStatus.SUCCESSFUL_SCAN;
		
		deleteZipFile();
		return new ScanCheckResultBean(returnValue, testDate);
	}
	
	// For each category, find the channel vuln and severity and pass the other work off to another method.
	private void checkMap(List<?> map) {
		if (map == null)
			return;

		for (Object mapElement : map) {
			if (mapElement == null || !(mapElement instanceof HashMap<?, ?>))
				continue;
			
			Map<?, ?> mapElementHash = (HashMap<?,?>) mapElement;
			
			Object samples = mapElementHash.get("samples");
			if (samples == null || !(samples instanceof ArrayList<?>))
				continue;

			for (Object sample : (ArrayList<?>) samples) {
				if (sample == null || !(sample instanceof LinkedHashMap))
					continue;
				
				Map<?, ?> findingMap = (HashMap<?, ?>) sample;
									
				Object dir = findingMap.get("dir");
				if (dir != null && (dir instanceof String) && testDate == null) {
					testDate = attemptToParseDate(dir.toString());
					if (testDate != null)
						return;
				}
			}
		}
	}

	@Override
	public String getType() {
		return ScannerType.SKIPFISH.getFullName();
	}
}
