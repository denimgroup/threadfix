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
package com.denimgroup.threadfix.importer.impl;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import com.denimgroup.threadfix.importer.util.ZipFileUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.io.*;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.zip.ZipFile;

@Service
public class ScanTypeCalculationServiceImpl implements ScanTypeCalculationService {
	
	private final SanitizedLogger log = new SanitizedLogger(ScanTypeCalculationService.class);

    public static final String TEMP_FILE_NAME = "tempFile";

    @Autowired
	private ApplicationDao applicationDao;
    @Autowired
	private ApplicationChannelDao applicationChannelDao;
    @Autowired
	private ChannelTypeDao channelTypeDao;

	private String getScannerType(MultipartFile file) {

		saveFile(TEMP_FILE_NAME,file);

        String returnValue = getScannerType(file.getOriginalFilename(), TEMP_FILE_NAME);

        deleteFile(TEMP_FILE_NAME);

        return returnValue;
	}

    // package access is for testing
    // the two arguments are needed to reconcile MultipartFile / File difference
    String getScannerType(String originalName, String fileName) {
        String returnString = null;

        if (ScanUtils.isZip(fileName)) {
            returnString = figureOutZip(fileName);
        } else if (originalName.endsWith("json")){
            //probably brakeman
            returnString = ScannerType.BRAKEMAN.getFullName();
        } else {
            returnString = figureOutXml(fileName);
        }

        return returnString;
    }
	
	// We currently only have zip files for skipfish and fortify
	// if we support a few more it would be worth a more modular style
	private String figureOutZip(String fileName) {
		
		String result = null;
		try (ZipFile zipFile = new ZipFile(fileName)) {
			if (zipFile.getEntry("audit.fvdl") != null) {
				result = ScannerType.FORTIFY.getFullName();
			} else if (ZipFileUtils.getZipEntry("issue_index.js", zipFile) != null){
				result = ScannerType.SKIPFISH.getFullName();
			}
		} catch (FileNotFoundException e) {
			log.warn("Unable to find zip file.", e);
		} catch (IOException e) {
			log.warn("Exception encountered while trying to identify zip file.", e);
		}
		
		return result;
	}

	private String figureOutXml(String fileName) {
		try {
			TagCollector collector = new TagCollector();
			
			InputStream stream = new FileInputStream(fileName);
			
			ScanUtils.readSAXInput(collector, "Done.", stream);
			
			return getType(collector.tags);
		} catch (IOException e) {
			log.error("Encountered IOException. Returning null.", e);
		}
		
		return null;
	}
	
	private static final Set<Entry<String, String[]>> map = new HashSet<>();
	static {
		addToMap(ScannerType.APPSCAN_DYNAMIC.getFullName(), "XmlReport", "AppScanInfo", "Version", "ServicePack", "Summary", "TotalIssues");
		addToMap(ScannerType.ARACHNI.getFullName(), "arachni_report", "title", "generated_on", "report_false_positives", "system", "version", "revision");
		addToMap(ScannerType.BURPSUITE.getFullName(), "issues", "issue", "serialNumber", "type", "name", "host", "path");
		addToMap(ScannerType.NETSPARKER.getFullName(), "netsparker");
		addToMap(ScannerType.CAT_NET.getFullName(), "Report", "Analysis", "AnalysisEngineVersion", "StartTimeStamp", "StopTimeStamp", "ElapsedTime");
		addToMap(ScannerType.W3AF.getFullName(), "w3afrun");
		addToMap(ScannerType.NESSUS.getFullName(), "NessusClientData_v2");
		addToMap(ScannerType.WEBINSPECT.getFullName(), "Sessions", "Session", "URL", "Scheme", "Host", "Port");
		addToMap(ScannerType.ACUNETIX_WVS.getFullName(),  "ScanGroup", "Scan", "Name", "ShortName", "StartURL", "StartTime");
		addToMap(ScannerType.FINDBUGS.getFullName(), "BugCollection", "Project", "BugInstance", "Class");
		addToMap(ScannerType.APPSCAN_SOURCE.getFullName(), "AssessmentRun", "AssessmentStats" );
		addToMap(ScannerType.MANUAL.getFullName(), "Vulnerabilities", "Vulnerability");
		addToMap(ScannerType.NTO_SPIDER.getFullName(), "VULNS", "VULNLIST");
		addToMap(ScannerType.NTO_SPIDER.getFullName(), "VulnSummary");
		addToMap(ScannerType.APPSCAN_ENTERPRISE.getFullName(), "report", "control", "row");
		addToMap(ScannerType.ZAPROXY.getFullName(), "report", "alertitem");
		addToMap(ScannerType.ZAPROXY.getFullName(), "OWASPZAPReport", "site", "alerts");
		addToMap(ScannerType.DEPENDENCY_CHECK.getFullName(), "analysis");
        addToMap(ScannerType.CHECKMARX.getFullName(), "CxXMLResults");
	}
	
	private static void addToMap(String name, String... tags) {
		map.add(new SimpleEntry<>(name, tags));
	}
	
	private String getType(List<String> scanTags) {
		
		for (Entry<String, String[]> entry : map) {
			if (matches(scanTags, entry.getValue())) {
				return entry.getKey();
			}
		}
		
		return null;
	}
	
	private boolean matches(List<String> scanTags, String[] channelTags) {
		
		if (scanTags.size() >= channelTags.length) {
			for (int i = 0; i < channelTags.length; i++) {
				if (!scanTags.get(i).equals(channelTags[i])) {
					return false;
				}
				
				if (i == channelTags.length - 1) {
					return true;
				}
			}
		}
		
		return false;
	}
	
	private void deleteFile(String fileName) {
		File file = new File(fileName);
		if (file.exists() && !file.delete()) {
			log.warn("Something went wrong trying to delete the file.");
			
			file.deleteOnExit();
		}
	}
	
	public class TagCollector extends DefaultHandler {
		public List<String> tags = new ArrayList<>();
		private int index = 0;
		
	    @Override
		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
    		if (index++ > 10) {
	    		throw new SAXException("Done.");
	    	}
    		
    		tags.add(qName);
	    }
	}
	
	@Override
	public Integer calculateScanType(int appId, MultipartFile file, String channelIdString) {
		ChannelType type = null;
		
		Integer channelId = null;
		if (channelIdString != null && !channelIdString.trim().isEmpty()) {
			channelId = IntegerUtils.getIntegerOrNull(channelIdString);
		}
		
		if (channelId == null || channelId == -1) {
			String typeString = getScannerType(file);
			if (typeString != null && !typeString.trim().isEmpty()) {
				type = channelTypeDao.retrieveByName(typeString);
			} else {
				return null;
			}
		} else {
			type = channelTypeDao.retrieveById(channelId);
		}
		
		if (type != null) {
			ApplicationChannel channel = applicationChannelDao.retrieveByAppIdAndChannelId(
					appId, type.getId());
			if (channel != null) {
				return channel.getId();
			} else {
				Application application = applicationDao.retrieveById(appId);
				channel = new ApplicationChannel();
				channel.setChannelType(type);
				application.getChannelList().add(channel);
				channel.setApplication(application);
				channel.setScanList(new ArrayList<Scan>());
				
				channel.setApplication(application);
				if (!isDuplicate(channel)) {
					applicationChannelDao.saveOrUpdate(channel);
					return channel.getId();
				}
			}
		}
		return null;
	}
	
	public boolean isDuplicate(ApplicationChannel applicationChannel) {
		if (applicationChannel.getApplication() == null
				|| applicationChannel.getChannelType().getId() == null) {
			return true;
		}
		
		ApplicationChannel dbAppChannel = applicationChannelDao.retrieveByAppIdAndChannelId(
				applicationChannel.getApplication().getId(), applicationChannel.getChannelType()
						.getId());
		return dbAppChannel != null && !applicationChannel.getId().equals(dbAppChannel.getId());
	}
	
	@Override
	public String saveFile(Integer channelId, MultipartFile file) {
		if (channelId == null || file == null) {
			log.warn("The scan upload file failed to save, it had null input.");
			return null;
		}
		
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);
		
		if (applicationChannel == null) {
			log.warn("Unable to retrieve Application Channel - scan save failed.");
			return null;
		}
		
		if (applicationChannel.getScanCounter() == null) {
			applicationChannel.setScanCounter(1);
		}
		
		String inputFileName = "scan-file-" + applicationChannel.getId() + "-" + applicationChannel.getScanCounter();

		applicationChannel.setScanCounter(applicationChannel.getScanCounter() + 1);
		
		applicationChannelDao.saveOrUpdate(applicationChannel);
		
		return saveFile(inputFileName,file);
	}
	
	private String saveFile(String inputFileName, MultipartFile file) {
        String returnValue = null;

		try (InputStream stream = file.getInputStream()) {

            File diskFile = new File(inputFileName);
            try (FileOutputStream out = new FileOutputStream(diskFile)) {
                byte[] buf = new byte[1024];
                int len;

                while ((len = stream.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }

                returnValue = inputFileName;

            } catch (IOException e) {
                log.warn("Writing the file stream to disk encountered an IOException.", e);
            }
		} catch (IOException e) {
            log.warn("Failed to retrieve an InputStream from the file upload.", e);
		}

		return returnValue;
	}
}
