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
package com.denimgroup.threadfix.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.EmptyScan;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.channel.ChannelImporter;
import com.denimgroup.threadfix.service.channel.ChannelImporterFactory;
import com.denimgroup.threadfix.service.queue.QueueSender;

// TODO figure out this Transactional stuff
// TODO reorganize methods - not in a very good order right now.
@Service
@Transactional(readOnly = false)
public class ScanServiceImpl implements ScanService {
	
	private final Log log = LogFactory.getLog("ScanService");

	private ScanDao scanDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	private VulnerabilityMapLogDao vulnerabilityMapLogDao = null;
	private EmptyScanDao emptyScanDao = null;
	private QueueSender queueSender = null;

	@Autowired
	public ScanServiceImpl(ScanDao scanDao, ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao,
			GenericVulnerabilityDao genericVulnerabilityDao,
			ApplicationChannelDao applicationChannelDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			EmptyScanDao emptyScanDao,
			QueueSender queueSender) {
		this.scanDao = scanDao;
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.applicationChannelDao = applicationChannelDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.emptyScanDao = emptyScanDao;
		this.queueSender = queueSender;
		this.genericVulnerabilityDao = genericVulnerabilityDao;
	}

	@Override
	public List<Scan> loadAll() {
		return scanDao.retrieveAll();
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
	public void saveFileAndAddToQueue(Integer channelId, MultipartFile file) {
		if (file == null || channelId == null)
			return;
		
		ApplicationChannel applicationChannel = applicationChannelDao
			.retrieveById(channelId);
		
		String fileName = saveFile(applicationChannel, file);

		Integer appId = applicationChannel.getApplication().getId();
		Integer orgId = applicationChannel.getApplication()
				.getOrganization().getId();

		queueSender.addScanToQueue(fileName, channelId, orgId, appId);
	}

	private String saveFile(ApplicationChannel applicationChannel, MultipartFile file) {
		if (applicationChannel == null || applicationChannel.getId() == null || 
				file == null) {
			log.warn("The scan upload file failed to save, it had null input.");
			return null;
		}
		
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

		if (applicationChannel.getScanCounter() == null)
			applicationChannel.setScanCounter(1);
		
		String inputFileName = "scan-file-" + applicationChannel.getId() + "-" + applicationChannel.getScanCounter();

		applicationChannel.setScanCounter(applicationChannel.getScanCounter() + 1);
		
		applicationChannelDao.saveOrUpdate(applicationChannel);
		
		File diskFile = new File(inputFileName);

		try {
			FileOutputStream out = new FileOutputStream(diskFile);

			byte[] buf = new byte[1024];
			int len = 0;

			while ((len = stream.read(buf)) > 0) {
				out.write(buf, 0, len);
			}

			out.close();
		} catch (IOException e) {
			log.warn("Writing the file stream to disk encountered an IOException.", e);
		}
		
		return inputFileName;
	}
	
	@Override
	public String checkFile(Integer channelId, MultipartFile file) {
		if (channelId == null || file == null) {
			log.warn("Scan file checking failed because there was null input.");
			return ChannelImporter.NULL_INPUT_ERROR;
		}
		
		ApplicationChannel channel = applicationChannelDao.retrieveById(channelId);
		
		if (channel == null) {
			log.warn("The ApplicationChannel could not be loaded.");
			return ChannelImporter.OTHER_ERROR;
		}
		
		ChannelImporterFactory factory = new ChannelImporterFactory(
				channelTypeDao, channelVulnerabilityDao, channelSeverityDao,
				genericVulnerabilityDao, vulnerabilityMapLogDao);
		
		ChannelImporter importer = factory.getChannelImporter(channel);
		
		if (importer == null) {
			log.warn("No importer could be loaded for the ApplicationChannel.");
			return ChannelImporter.OTHER_ERROR;
		}
		
		try {
			importer.setFile(file);
		} catch (IOException e) {
			log.warn("There was an IO error setting the file for the scan.", e);
			return ChannelImporter.OTHER_ERROR;
		}
		
		String result = importer.checkFile();
		
		if (result == null) {
			log.warn("The checkFile() method of the importer returned null, check to make sure that it is implemented correctly.");
			return ChannelImporter.OTHER_ERROR;
		} else {
			return result;
		}
	}

	@Override
	public Integer saveEmptyScanAndGetId(Integer channelId, MultipartFile file) {
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);
			
		String fileName = saveFile(applicationChannel, file);
		
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
		
		queueSender.addScanToQueue(fileName, applicationChannel.getId(), orgId, appId);
	
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
	public String checkRPCFile(Integer channelId, String scanContents) {
		if (channelId == null || scanContents == null)
			return ChannelImporter.NULL_INPUT_ERROR;
		
		String fileName = null;
		
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);
		
		if (applicationChannel == null)
			return ChannelImporter.OTHER_ERROR;
		
		if (applicationChannel.getId() != null) {
			if (applicationChannel.getScanCounter() == null)
				applicationChannel.setScanCounter(1);
			fileName = "scan-file-rpc-test-" + applicationChannel.getId() + "-" + applicationChannel.getScanCounter();
		} else {
			fileName = "scan-file-rpc-test-" + String.valueOf(new Random().nextLong());
		}
		
		File diskFile = new File(fileName);
		
		byte[] tempContents = Base64.decodeBase64(scanContents.getBytes());
		try {
			FileUtils.writeByteArrayToFile(diskFile, tempContents);
		} catch (IOException e) {
			log.warn("Writing the RPC file to disk failed.",e);
		}
		
		ChannelImporterFactory factory = new ChannelImporterFactory(
				channelTypeDao, channelVulnerabilityDao, channelSeverityDao,
				genericVulnerabilityDao, vulnerabilityMapLogDao);
		
		ChannelImporter importer = factory
				.getChannelImporter(applicationChannel);
		
		if (importer == null) {
			if (!diskFile.delete()) {
				diskFile.deleteOnExit();
			}
			return ChannelImporter.OTHER_ERROR;
		}
		
		importer.setFileName(fileName);
		
		String result = importer.checkFile();
		
		importer.deleteScanFile();
		
		if (result == null) {
			log.warn("The checkFile() method of the importer returned null, check to make sure that it is implemented correctly.");
			return ChannelImporter.OTHER_ERROR;
		} else {
			return result;
		}
	}
}