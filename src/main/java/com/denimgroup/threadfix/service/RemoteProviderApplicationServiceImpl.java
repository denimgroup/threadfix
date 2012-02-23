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

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
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
	private VulnerabilityMapLogDao vulnerabilityMapLogDao = null;
	private RemoteProviderApplicationDao remoteProviderApplicationDao = null;
	private ScanMergeService scanMergeService = null;
	
	@Autowired
	public RemoteProviderApplicationServiceImpl(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			RemoteProviderApplicationDao remoteProviderApplicationDao,
			ScanMergeService scanMergeService) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.remoteProviderApplicationDao = remoteProviderApplicationDao;
		this.scanMergeService = scanMergeService;
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
		
		// We can't use remoteProviderType.getRemoteProviderApplications() because the old session is closed
		List<RemoteProviderApplication> appsForType = loadAllWithTypeId(remoteProviderType.getId());
		
		if (newApps == null || newApps.size() == 0) {
			return;
		} else {
			
			Set<String> appIds = new TreeSet<String>();
			if (appsForType != null && appsForType.size() > 0) {
				for (RemoteProviderApplication app : appsForType) {
					appIds.add(app.getNativeId());
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
	public List<RemoteProviderApplication> getApplications(RemoteProviderType remoteProviderType) {
		if (remoteProviderType == null) {
			return null;
		}
		
		List<RemoteProviderApplication> newApps = 
				getRemoteProviderFactory().fetchApplications(remoteProviderType);
		
		if (newApps == null || newApps.size() == 0) {
			return null;
		}
		
		for (RemoteProviderApplication app : newApps) {
			app.setRemoteProviderType(remoteProviderType);
		}
		
		return newApps;
	}
	
	@Override
	public void deleteApps(RemoteProviderType remoteProviderType) {
		if (remoteProviderType != null && remoteProviderType.getRemoteProviderApplications() != null) {
			for (RemoteProviderApplication app : remoteProviderType.getRemoteProviderApplications()) {
				remoteProviderApplicationDao.deleteRemoteProviderApplication(app);
			}
		}
	}
	
	@Override
	public void importScanForApplication(RemoteProviderApplication remoteProviderApplication) {
		if (remoteProviderApplication == null)
			return;
		
		Scan resultScan = getRemoteProviderFactory().fetchScan(remoteProviderApplication);
		
		if (resultScan != null && resultScan.getFindings() != null && resultScan.getFindings().size() != 0) {
			log.info("Scan was parsed and has findings, passing to ScanMergeService.");
			scanMergeService.processRemoteScan(resultScan);
		} else {
			log.info("Remote Scan import died.");
		}
	}
	
	private RemoteProviderFactory getRemoteProviderFactory() {
		return new RemoteProviderFactory(channelTypeDao, 
				channelVulnerabilityDao, channelSeverityDao, vulnerabilityMapLogDao);
	}
}
