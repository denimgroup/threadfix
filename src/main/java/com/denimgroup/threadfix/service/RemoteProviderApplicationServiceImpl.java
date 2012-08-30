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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.remoteprovider.RemoteProviderFactory;

@Service
@Transactional(readOnly = false)
public class RemoteProviderApplicationServiceImpl implements
		RemoteProviderApplicationService {
	
	private final Log log = LogFactory.getLog("RemoteProviderApplicationService");
	
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private RemoteProviderApplicationDao remoteProviderApplicationDao = null;
	private ScanMergeService scanMergeService = null;
	private ApplicationDao applicationDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	
	@Autowired
	public RemoteProviderApplicationServiceImpl(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, 
			ChannelSeverityDao channelSeverityDao,
			RemoteProviderApplicationDao remoteProviderApplicationDao,
			ScanMergeService scanMergeService,
			ApplicationDao applicationDao,
			ApplicationChannelDao applicationChannelDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.remoteProviderApplicationDao = remoteProviderApplicationDao;
		this.scanMergeService = scanMergeService;
		this.applicationDao = applicationDao;
		this.applicationChannelDao = applicationChannelDao;
	}
	
	@Override
	public RemoteProviderApplication load(int id) {
		return remoteProviderApplicationDao.retrieveById(id);
	}
	
	@Override
	public List<RemoteProviderApplication> loadAllWithTypeId(int id) {
		return remoteProviderApplicationDao.retrieveAllWithTypeId(id);
	}

	@Override
	public void store(RemoteProviderApplication remoteProviderApplication) {
		remoteProviderApplicationDao.saveOrUpdate(remoteProviderApplication);
	}
	
	@Override
	public void updateApplications(RemoteProviderType remoteProviderType) {

		List<RemoteProviderApplication> newApps = getRemoteProviderFactory()
				.fetchApplications(remoteProviderType);
		
		// We can't use remoteProviderType.getRemoteProviderApplications() 
		// because the old session is closed
		List<RemoteProviderApplication> appsForType = loadAllWithTypeId(
														remoteProviderType.getId());
		
		if (newApps == null || newApps.size() == 0) {
			return;
		} else {
			
			Set<String> appIds = new TreeSet<String>();
			if (appsForType != null && appsForType.size() > 0) {
				for (RemoteProviderApplication app : appsForType) {
					if (app == null || app.getNativeId() == null) {
						continue;
					}
					
					if (app.getNativeId().length() >= RemoteProviderApplication.NATIVE_ID_LENGTH) {
						log.warn("A Remote Provider application came out of the database with more than " 
									+ RemoteProviderApplication.NATIVE_ID_LENGTH 
									+ " characters in it. This shouldn't be possible.");
						appIds.add(app.getNativeId().substring(0, RemoteProviderApplication.NATIVE_ID_LENGTH-1));
					} else {
						appIds.add(app.getNativeId());
					}
				}
			}
			
			for (RemoteProviderApplication app : newApps) {
				if (app != null && !appIds.contains(app.getNativeId())) {
					app.setRemoteProviderType(remoteProviderType);
					appsForType.add(app);
					remoteProviderType.setRemoteProviderApplications(appsForType);
					store(app);
				}
			}
		}
	}
	
	@Override
	public List<RemoteProviderApplication> getApplications(
			RemoteProviderType remoteProviderType) {
		if (remoteProviderType == null) {
			return null;
		}
		
		List<RemoteProviderApplication> newApps = 
				getRemoteProviderFactory().fetchApplications(remoteProviderType);
		
		if (newApps == null || newApps.size() == 0) {
			return null;
		}
		
		if (newApps != null && newApps.size() > 1) {
			Collections.sort(newApps,
				new Comparator<RemoteProviderApplication>() {
					public int compare(RemoteProviderApplication f1, 
							RemoteProviderApplication f2)
		            {
		                return f1.getNativeId().compareTo(f2.getNativeId());
		            }
		        });
		}
		
		for (RemoteProviderApplication app : newApps) {
			if (app == null) {
				continue;
			}
			
			if (app.getNativeId() != null && 
					app.getNativeId().length() >= RemoteProviderApplication.NATIVE_ID_LENGTH) {
				log.warn("A Remote Provider application was parsed that has more than " 
							+ RemoteProviderApplication.NATIVE_ID_LENGTH 
							+ " characters in it. The name is being trimmed but this"
							+ " should not prevent use of the application");
				app.setNativeId(app.getNativeId().substring(0, RemoteProviderApplication.NATIVE_ID_LENGTH-1));
			}
			
			app.setRemoteProviderType(remoteProviderType);
		}
		
		return newApps;
	}
	
	@Override
	public void deleteApps(RemoteProviderType remoteProviderType) {
		if (remoteProviderType != null && remoteProviderType
				.getRemoteProviderApplications() != null) {
			for (RemoteProviderApplication app : remoteProviderType
					.getRemoteProviderApplications()) {
				remoteProviderApplicationDao.deleteRemoteProviderApplication(app);
			}
		}
	}
	
	@Override
	@Transactional
	public boolean importScansForApplication(
			RemoteProviderApplication remoteProviderApplication) {
		if (remoteProviderApplication == null)
			return false;
		
		List<Scan> resultScans = getRemoteProviderFactory().fetchScans(remoteProviderApplication);
		
		boolean success = false;
		if (resultScans != null && resultScans.size() > 0) {
			Collections.sort(resultScans, new Comparator<Scan>() {
				public int compare(Scan scan1, Scan scan2){
					Calendar scan1Time = scan1.getImportTime();
					Calendar scan2Time = scan2.getImportTime();
					
					if (scan1Time == null || scan2Time == null) 
						return 0;
					
					return scan1Time.compareTo(scan2Time);
				}
			});
			
			for (Scan resultScan : resultScans) {
				if (resultScan == null || resultScan.getFindings() == null 
						|| resultScan.getFindings().size() == 0) {
					log.warn("Remote Scan import returned a null scan or a scan with no findings.");
					
				} else if (remoteProviderApplication.getLastImportTime() != null && 
							(resultScan.getImportTime() == null ||
							!remoteProviderApplication.getLastImportTime().before(
									resultScan.getImportTime()))) {
					log.warn("Remote Scan was not newer than the last imported scan " +
							"for this RemoteProviderApplication.");
					
				} else {
					log.info("Scan was parsed and has findings, passing to ScanMergeService.");
					
					remoteProviderApplication.setLastImportTime(resultScan.getImportTime());
					
					remoteProviderApplicationDao.saveOrUpdate(remoteProviderApplication);
					
					if (resultScan.getApplicationChannel().getScanList() == null) {
						resultScan.getApplicationChannel().setScanList(new ArrayList<Scan>());
					}
					
					if (!resultScan.getApplicationChannel().getScanList().contains(resultScan)) {
						resultScan.getApplicationChannel().getScanList().add(resultScan);
					}
				
					scanMergeService.processRemoteScan(resultScan);
					success = true;
				}
			}
		}
		
		return success;
	}
	
	private RemoteProviderFactory getRemoteProviderFactory() {
		return new RemoteProviderFactory(channelTypeDao, 
				channelVulnerabilityDao, channelSeverityDao);
	}

	@Override
	public void processApp(BindingResult result, 
			RemoteProviderApplication remoteProviderApplication) {

		Application application = applicationDao.retrieveById(
				remoteProviderApplication.getApplication().getId());
		
		if (application == null) {
			result.rejectValue("application.id", "errors.invalid", 
					new String[] {"Application"},"Application choice was invalid.");
			return;
		}
		
		if (application.getRemoteProviderApplications() == null) {
			application.setRemoteProviderApplications(
					new ArrayList<RemoteProviderApplication>());
		}
		if (!application.getRemoteProviderApplications().contains(remoteProviderApplication)) {
			application.getRemoteProviderApplications().add(remoteProviderApplication);
			remoteProviderApplication.setApplication(application);
		}
		
		ChannelType type = remoteProviderApplication.getRemoteProviderType().getChannelType();
		
		if (application.getChannelList() == null || application.getChannelList().size() == 0) {
			application.setChannelList(new ArrayList<ApplicationChannel>());
		}
		
		Integer previousId = null;
		
		if (remoteProviderApplication.getApplicationChannel() != null) {
			previousId = remoteProviderApplication.getApplicationChannel().getId();
		}
		
		remoteProviderApplication.setApplicationChannel(null);
		
		for (ApplicationChannel applicationChannel : application.getChannelList()) {
			if (applicationChannel.getChannelType().getName().equals(type.getName())) {
				remoteProviderApplication.setApplicationChannel(applicationChannel);
				if (applicationChannel.getScanList() != null && 
						applicationChannel.getScanList().size() > 0) {
					List<Scan> scans = applicationChannel.getScanList();
					Collections.sort(scans,Scan.getTimeComparator());
					remoteProviderApplication.setLastImportTime(
							scans.get(scans.size() - 1).getImportTime());
				} else {
					remoteProviderApplication.setLastImportTime(null);
				}
				break;
			}
		}
		
		if (remoteProviderApplication.getApplicationChannel() == null) {
			ApplicationChannel channel = new ApplicationChannel();
			channel.setApplication(application);
			if (remoteProviderApplication.getRemoteProviderType() != null && 
				  remoteProviderApplication.getRemoteProviderType().getChannelType() != null) {
				channel.setChannelType(remoteProviderApplication.
						getRemoteProviderType().getChannelType());
				applicationChannelDao.saveOrUpdate(channel);
			}
			remoteProviderApplication.setLastImportTime(null);
			remoteProviderApplication.setApplicationChannel(channel);
			application.getChannelList().add(channel);
		}
		
		if (remoteProviderApplication.getApplicationChannel() == null
				|| previousId == null
				|| !previousId.equals(remoteProviderApplication
						.getApplicationChannel().getId())) {
			
			store(remoteProviderApplication);
			applicationDao.saveOrUpdate(application);
		}
	}
	
	@Override
	public List<RemoteProviderApplication> loadAllWithMappings() {
		return remoteProviderApplicationDao.retrieveAllWithMappings();
	}
}
