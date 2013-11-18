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
import java.util.Calendar;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.EmptyScan;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.plugin.scanner.ChannelImporterFactory;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ChannelImporter;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ScanImportStatus;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

// TODO figure out this Transactional stuff
// TODO make another service to hold the scan history controller stuff
@Service
@Transactional(readOnly = false)
public class ScanServiceImpl implements ScanService {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanService");
	
	private ScanDao scanDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private EmptyScanDao emptyScanDao = null;
	private QueueSender queueSender = null;
	private PermissionService permissionService = null;

	@Autowired
	public ScanServiceImpl(ScanDao scanDao,
			ApplicationChannelDao applicationChannelDao,
			EmptyScanDao emptyScanDao,
			PermissionService permissionService,
			QueueSender queueSender) {
		this.scanDao = scanDao;
		this.applicationChannelDao = applicationChannelDao;
		this.emptyScanDao = emptyScanDao;
		this.queueSender = queueSender;
		this.permissionService = permissionService;
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
	public ScanCheckResultBean checkFile(Integer channelId, String fileName) {
		if (channelId == null || fileName == null) {
			log.warn("Scan file checking failed because there was null input.");
			return new ScanCheckResultBean(ScanImportStatus.NULL_INPUT_ERROR);
		}
		
		ApplicationChannel channel = applicationChannelDao.retrieveById(channelId);
		
		if (channel == null) {
			log.warn("The ApplicationChannel could not be loaded.");
			return new ScanCheckResultBean(ScanImportStatus.OTHER_ERROR);
		}
		
		ChannelImporter importer = ChannelImporterFactory.getChannelImporter(channel);
		
		if (importer == null) {
			log.warn("No importer could be loaded for the ApplicationChannel.");
			return  new ScanCheckResultBean(ScanImportStatus.OTHER_ERROR);
		}
				
		importer.setFileName(fileName);
		
		ScanCheckResultBean result = importer.checkFile();
		
		if (result == null || result.getScanCheckResult() == null || 
				(!result.getScanCheckResult().equals(ScanImportStatus.SUCCESSFUL_SCAN)
				&& !result.getScanCheckResult().equals(ScanImportStatus.EMPTY_SCAN_ERROR))) {
			importer.deleteScanFile();
		}
		
		Calendar scanQueueDate = applicationChannelDao.getMostRecentQueueScanTime(channel.getId());
		
		if (scanQueueDate != null && result != null && result.getTestDate() != null &&
				!result.getTestDate().after(scanQueueDate)) {
			log.warn(ScanImportStatus.MORE_RECENT_SCAN_ON_QUEUE.toString());
			return new ScanCheckResultBean(ScanImportStatus.MORE_RECENT_SCAN_ON_QUEUE, result.getTestDate());
		}

		if (result == null) {
			log.warn("The checkFile() method of the importer returned null, check to make sure that it is implemented correctly.");
			return new ScanCheckResultBean(ScanImportStatus.OTHER_ERROR);
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
	public List<Scan> loadMostRecentFiltered(int number) {
		if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
			return scanDao.retrieveMostRecent(number);
		}
		
		Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();
		
		return scanDao.retrieveMostRecent(number, appIds, teamIds);
	}
	
	@Override
	public int getScanCount() {
		if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
			return scanDao.getScanCount();
		}
		
		Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();
		
		return scanDao.getScanCount(appIds, teamIds);
	}
	
	@Override
	public List<Scan> getTableScans(Integer page) {
		if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
			return scanDao.getTableScans(page);
		}
		
		Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();
		
		return scanDao.getTableScans(page, appIds, teamIds);
	}
	
}