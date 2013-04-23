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
package com.denimgroup.threadfix.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.EmptyScan;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.channel.ChannelImporter;
import com.denimgroup.threadfix.service.channel.ChannelImporterFactory;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

// TODO figure out this Transactional stuff
// TODO reorganize methods - not in a very good order right now.
@Service
@Transactional(readOnly = false)
public class ScanServiceImpl implements ScanService {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanService");
	
	private ApplicationDao applicationDao = null;
	private ScanDao scanDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	private EmptyScanDao emptyScanDao = null;
	private QueueSender queueSender = null;

	@Autowired
	public ScanServiceImpl(ScanDao scanDao, ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao,
			GenericVulnerabilityDao genericVulnerabilityDao,
			ApplicationDao applicationDao,
			ApplicationChannelDao applicationChannelDao,
			EmptyScanDao emptyScanDao,
			QueueSender queueSender) {
		this.scanDao = scanDao;
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.applicationChannelDao = applicationChannelDao;
		this.emptyScanDao = emptyScanDao;
		this.applicationDao = applicationDao;
		this.queueSender = queueSender;
		this.genericVulnerabilityDao = genericVulnerabilityDao;
	}

	@Override
	public List<Scan> loadAll() {
		return scanDao.retrieveAll();
	}
	
	@Override
	public Integer calculateScanType(int appId, int orgId, MultipartFile file, String channelIdString) {
		ChannelType type = null;
		
		Integer channelId = -1;
		if (channelIdString != null && !channelIdString.trim().isEmpty()) {
			try {
				channelId = Integer.valueOf(channelIdString);
			} catch (NumberFormatException e) {
				log.error("channelId was not null and was not a number.");
			}
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
	public Scan loadScan(Integer scanId) {
		return scanDao.retrieveById(scanId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeScan(Scan scan) {
		scanDao.saveOrUpdate(scan);
	}

	@Override
	@Transactional(readOnly = false)
	public void addFileToQueue(Integer channelId, String fileName, Calendar scanDate) {
		if (fileName == null || channelId == null)
			return;
		
		ApplicationChannel applicationChannel = applicationChannelDao
			.retrieveById(channelId);
		
		Integer appId = applicationChannel.getApplication().getId();
		Integer orgId = applicationChannel.getApplication()
				.getOrganization().getId();

		queueSender.addScanToQueue(fileName, channelId, orgId, appId, scanDate, applicationChannel);
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
		
		if (applicationChannel.getScanCounter() == null)
			applicationChannel.setScanCounter(1);
		
		String inputFileName = "scan-file-" + applicationChannel.getId() + "-" + applicationChannel.getScanCounter();

		applicationChannel.setScanCounter(applicationChannel.getScanCounter() + 1);
		
		applicationChannelDao.saveOrUpdate(applicationChannel);
		
		return saveFile(inputFileName,file);
	}
	
	private String saveFile(String inputFileName, MultipartFile file) {
		InputStream stream = null;
		try {
			stream = file.getInputStream();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		if (stream == null) {
			log.warn("Failed to retrieve an InputStream from the file upload.");
			return null;
		}
		
		File diskFile = new File(inputFileName);
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(diskFile);

			byte[] buf = new byte[1024];
			int len = 0;

			while ((len = stream.read(buf)) > 0) {
				out.write(buf, 0, len);
			}

			out.close();
		} catch (IOException e) {
			log.warn("Writing the file stream to disk encountered an IOException.", e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				log.warn("IOException encountered while attempting to close a stream.", e);
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					log.warn("IOException encountered while attempting to close a stream.", e);
				}
			}
		}
		
		return inputFileName;
	}
	
	@Override
	public ScanCheckResultBean checkFile(Integer channelId, String fileName) {
		if (channelId == null || fileName == null) {
			log.warn("Scan file checking failed because there was null input.");
			return new ScanCheckResultBean(ChannelImporter.NULL_INPUT_ERROR);
		}
		
		ApplicationChannel channel = applicationChannelDao.retrieveById(channelId);
		
		if (channel == null) {
			log.warn("The ApplicationChannel could not be loaded.");
			return new ScanCheckResultBean(ChannelImporter.OTHER_ERROR);
		}
		
		ChannelImporterFactory factory = new ChannelImporterFactory(
				channelTypeDao, channelVulnerabilityDao, channelSeverityDao,
				genericVulnerabilityDao);
		
		ChannelImporter importer = factory.getChannelImporter(channel);
		
		if (importer == null) {
			log.warn("No importer could be loaded for the ApplicationChannel.");
			return  new ScanCheckResultBean(ChannelImporter.OTHER_ERROR);
		}
				
		importer.setFileName(fileName);
		
		ScanCheckResultBean result = importer.checkFile();
		
		if (result == null || result.getScanCheckResult() == null|| 
				(!result.getScanCheckResult().equals(ChannelImporter.SUCCESSFUL_SCAN)
				&& !result.equals(ChannelImporter.EMPTY_SCAN_ERROR))) {
			importer.deleteScanFile();
		}
		
		Calendar scanQueueDate = applicationChannelDao.getMostRecentQueueScanTime(channel.getId());
		
		if (scanQueueDate != null && result.getTestDate() != null && 
				!result.getTestDate().after(scanQueueDate)) {
			String status = "There is a more recent " + channel.getChannelType().getName() + 
								" scan on the queue for this application.";
			log.warn(status);
			return new ScanCheckResultBean(status, result.getTestDate());
		}

		if (result == null) {
			log.warn("The checkFile() method of the importer returned null, check to make sure that it is implemented correctly.");
			return new ScanCheckResultBean(ChannelImporter.OTHER_ERROR);
		} else {
			return result;
		}
	}

	@Override
	public Integer saveEmptyScanAndGetId(Integer channelId, String fileName) {
			
		if (fileName == null) {
			log.warn("Saving the empty file failed. Check filesystem permissions.");
			return null;
		} else {
			EmptyScan emptyScan = new EmptyScan();
			emptyScan.setApplicationChannel(applicationChannelDao.retrieveById(channelId));
			emptyScan.setAlreadyProcessed(false);
			emptyScan.setDateUploaded(Calendar.getInstance());
			emptyScan.setFileName(fileName);
			emptyScanDao.saveOrUpdate(emptyScan);
			return emptyScan.getId();
		}
	}
	
	@Override
	public void addEmptyScanToQueue(Integer emptyScanId) {
		EmptyScan emptyScan = emptyScanDao.retrieveById(emptyScanId);
		
		if (emptyScan.getAlreadyProcessed() ||
				emptyScan.getApplicationChannel() == null ||
				emptyScan.getApplicationChannel().getId() == null ||
				emptyScan.getApplicationChannel().getApplication() == null ||
				emptyScan.getApplicationChannel().getApplication().getId() == null ||
				emptyScan.getApplicationChannel().getApplication().getOrganization() == null ||
				emptyScan.getApplicationChannel().getApplication().getOrganization().getId() == null ||
				emptyScan.getFileName() == null) {
			log.warn("The empty scan was not added to the queue. It was either already processed or incorrectly configured.");
			return;
		}
		
		ApplicationChannel applicationChannel = emptyScan.getApplicationChannel();
		
		Integer appId = applicationChannel.getApplication().getId();
		Integer orgId = applicationChannel.getApplication()
				.getOrganization().getId();

		String fileName = emptyScan.getFileName();
		
		queueSender.addScanToQueue(fileName, applicationChannel.getId(), orgId, appId, null, applicationChannel);
	
		emptyScan.setAlreadyProcessed(true);
		emptyScanDao.saveOrUpdate(emptyScan);
	}
	
	@Override
	public void deleteEmptyScan(Integer emptyScanId) {
		EmptyScan emptyScan = emptyScanDao.retrieveById(emptyScanId);
		
		if (emptyScan != null) {
			emptyScan.setAlreadyProcessed(true);
			File file = new File(emptyScan.getFileName());
			if (file.exists()) {
				if (!file.delete())
					file.deleteOnExit();
			}
			
			emptyScanDao.saveOrUpdate(emptyScan);
		}
	}
	
	@Override
	public long getFindingCount(Integer scanId) {
		return scanDao.getFindingCount(scanId);
	}

	@Override
	public long getUnmappedFindingCount(Integer scanId) {
		return scanDao.getFindingCountUnmapped(scanId);
	}

	// TODO bounds checking
	@Override
	public void loadStatistics(Scan scan) {
		if (scan == null || scan.getId() == null) {
			return;
		}
		scan.setNumWithoutGenericMappings((int) scanDao.getNumberWithoutGenericMappings(scan.getId()));
		scan.setTotalNumberSkippedResults((int) scanDao.getTotalNumberSkippedResults(scan.getId()));
		scan.setNumWithoutChannelVulns((int) scanDao.getNumberWithoutChannelVulns(scan.getId()));
		scan.setTotalNumberFindingsMergedInScan((int) scanDao.getTotalNumberFindingsMergedInScan(scan.getId()));
	}
	
	@Override
	public List<Scan> loadMostRecent(int number) {
		return scanDao.retrieveMostRecent(number);
	}
	
	@Override
	public String getScannerType(MultipartFile file) {
		String returnString = null;
		saveFile("tempFile",file);
		
		if (isZip("tempFile")) {
			returnString = figureOutZip("tempFile");
		} else if (file.getOriginalFilename().endsWith("json")){
			//probably brakeman
			returnString = ChannelType.BRAKEMAN;
		} else {
			returnString = figureOutXml("tempFile");
		}
		
		deleteFile("tempFile");
		
		return returnString;
	}
	
	private boolean isZip(String fileName) {
		RandomAccessFile file = null;
		try {
			file = new RandomAccessFile(new File(fileName), "r");  
			// these are the magic bytes for a zip file
	        return file.readInt() == 0x504B0304;
		} catch (FileNotFoundException e) {
			log.warn("The file was not found. Check the usage of this method.", e);
		} catch (IOException e) {
			log.warn("IOException. Weird.", e);
		} finally {
			if (file != null) {
				try {
					file.close();
				} catch (IOException e) {
					log.error("Encountered IOException when attempting to close a file.");
				}
			}
		}
		
		return false;
	}
	
	// We currently only have zip files for skipfish and fortify
	// if we support a few more it would be worth a more modular style
	private String figureOutZip(String fileName) {
		
		String result = null;
		ZipFile zipFile = null;
		try {
			zipFile = new ZipFile(fileName);
			ZipEntry firstFile = ((ZipEntry)zipFile.entries().nextElement());
			
			if (zipFile.getEntry("audit.fvdl") != null) {
				result = ChannelType.FORTIFY;
			} else if ((zipFile.getEntry("samples.js") != null && zipFile.getEntry("summary.js") != null)
					|| (firstFile.isDirectory() && firstFile.getName() != null &&
						(zipFile.getEntry(firstFile.getName() + "samples.js") != null && 
						zipFile.getEntry(firstFile.getName() + "summary.js") != null))) {
				result = ChannelType.SKIPFISH;
			}
		} catch (FileNotFoundException e) {
			log.warn("Unable to find zip file.", e);
		} catch (IOException e) {
			log.warn("Exception encountered while trying to identify zip file.", e);
		} finally {
			if (zipFile != null) {
				try {
					zipFile.close();
				} catch (IOException e) {
					log.warn("IOException encountered while trying to close the zip file.", e);
				}
			}
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
			log.error("Encountered IOException. Returning null.");
		}
		
		return null;
	}
	
	private static final Map<String, String[]> map = new HashMap<String, String[]>();
	static {
		addToMap(ChannelType.APPSCAN_DYNAMIC, "XmlReport", "AppScanInfo", "Version", "ServicePack", "Summary", "TotalIssues");
		addToMap(ChannelType.ARACHNI, "arachni_report", "title", "generated_on", "report_false_positives", "system", "version", "revision");
		addToMap(ChannelType.BURPSUITE, "issues", "issue", "serialNumber", "type", "name", "host", "path");
		addToMap(ChannelType.NETSPARKER, "netsparker", "target", "url", "scantime", "vulnerability", "url", "type", "severity");
		addToMap(ChannelType.CAT_NET, "Report", "Analysis", "AnalysisEngineVersion", "StartTimeStamp", "StopTimeStamp", "ElapsedTime");
		addToMap(ChannelType.W3AF, "w3afrun");
		addToMap(ChannelType.NESSUS, "NessusClientData_v2", "Policy", "policyName", "Preferences", "ServerPreferences");
		addToMap(ChannelType.WEBINSPECT, "Sessions", "Session", "URL", "Scheme", "Host", "Port");
		addToMap(ChannelType.ZAPROXY, "site", "alerts");
		addToMap(ChannelType.ACUNETIX_WVS,  "ScanGroup", "Scan", "Name", "ShortName", "StartURL", "StartTime");
		addToMap(ChannelType.FINDBUGS, "BugCollection", "Project", "BugInstance", "Class");
		addToMap(ChannelType.APPSCAN_SOURCE,  "AssessmentRun", "AssessmentStats" );
		addToMap(ChannelType.NTO_SPIDER, "VULNS","VULNLIST");
	}
	
	private static void addToMap(String name, String... tags) { map.put(name, tags); }
	
	private String getType(List<String> scanTags) {
		
		for (Entry<String, String[]> entry : map.entrySet())
		if (matches(scanTags, entry.getValue())) {
			return entry.getKey();
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
		public List<String> tags = new ArrayList<String>();
		private int index = 0;
		
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
    		if (index++ > 10) {
	    		throw new SAXException("Done.");
	    	}
    		
    		tags.add(qName);
	    }
	}
	
	@Override
	public int getScanCount() {
		return scanDao.getScanCount();
	}
	
	public List<Scan> getTableScans(Integer page) {
		return scanDao.getTableScans(page);
	}
	
}