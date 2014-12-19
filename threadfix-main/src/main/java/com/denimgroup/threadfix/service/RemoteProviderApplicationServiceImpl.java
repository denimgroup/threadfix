////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.util.*;

@Service
@Transactional(readOnly = false)
public class RemoteProviderApplicationServiceImpl implements
		RemoteProviderApplicationService {
	
	private final SanitizedLogger log = new SanitizedLogger("RemoteProviderApplicationService");
	
	private RemoteProviderApplicationDao remoteProviderApplicationDao = null;
	private ApplicationDao applicationDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private QueueSender queueSender = null;
    private RemoteProviderFactory remoteProviderFactory = null;
	
	@Autowired
	public RemoteProviderApplicationServiceImpl(
			RemoteProviderApplicationDao remoteProviderApplicationDao,
			ApplicationDao applicationDao,
			QueueSender queueSender,
            RemoteProviderFactory remoteProviderFactory,
			ApplicationChannelDao applicationChannelDao) {
		this.remoteProviderApplicationDao = remoteProviderApplicationDao;
		this.applicationDao = applicationDao;
		this.applicationChannelDao = applicationChannelDao;
		this.queueSender = queueSender;
        this.remoteProviderFactory = remoteProviderFactory;
	}
	
	@Override
	public RemoteProviderApplication load(int id) {
		return remoteProviderApplicationDao.retrieveById(id);
	}
	
	@Override
    @Nonnull
	public List<RemoteProviderApplication> loadAllWithTypeId(int id) {
		return remoteProviderApplicationDao.retrieveAllWithTypeId(id);
	}

	@Override
	public void store(RemoteProviderApplication remoteProviderApplication) {
		remoteProviderApplicationDao.saveOrUpdate(remoteProviderApplication);
	}
	
	@Override
	public List<RemoteProviderApplication> updateApplications(RemoteProviderType remoteProviderType) {

		List<RemoteProviderApplication> newApps =
                remoteProviderFactory.fetchApplications(remoteProviderType);
		
		// We can't use remoteProviderType.getRemoteProviderApplications()
		// because the old session is closed
		List<RemoteProviderApplication> appsForType = loadAllWithTypeId(
														remoteProviderType.getId());
		
		if (newApps != null && newApps.size() != 0) {
			Set<String> appIds = new TreeSet<>();
			if (appsForType.size() > 0) {
				for (RemoteProviderApplication app : appsForType) {
					if (app == null || app.getNativeName() == null) {
						continue;
					}
					
					if (app.getNativeName().length() >= RemoteProviderApplication.NATIVE_NAME_LENGTH) {
						log.warn("A Remote Provider application came out of the database with more than "
									+ RemoteProviderApplication.NATIVE_NAME_LENGTH
									+ " characters in it. This shouldn't be possible.");
						appIds.add(app.getNativeName().substring(0, RemoteProviderApplication.NATIVE_NAME_LENGTH-1));
					} else {
						appIds.add(app.getNativeName());
					}
				}
			}
			
			for (RemoteProviderApplication app : newApps) {
				if (app != null && !appIds.contains(app.getNativeName())) {
					app.setRemoteProviderType(remoteProviderType);
					appsForType.add(app);
					remoteProviderType.setRemoteProviderApplications(appsForType);
					store(app);
				}
			}
		}

        return appsForType;
	}
	
	@Override
	public List<RemoteProviderApplication> getApplications(
			RemoteProviderType remoteProviderType) {
		if (remoteProviderType == null) {
			return null;
		}
		
		List<RemoteProviderApplication> newApps =
                remoteProviderFactory.fetchApplications(remoteProviderType);
		
		if (newApps == null || newApps.size() == 0) {
			return null;
		}
		
		if (newApps.size() > 1) {
			Collections.sort(newApps,
				new Comparator<RemoteProviderApplication>() {
					@Override
					public int compare(RemoteProviderApplication f1,
							RemoteProviderApplication f2)
		            {
		                return f1.getNativeName().compareTo(f2.getNativeName());
		            }
		        });
		}
		
		for (RemoteProviderApplication app : newApps) {
			if (app == null) {
				continue;
			}
			
			if (app.getNativeName() != null &&
					app.getNativeName().length() >= RemoteProviderApplication.NATIVE_NAME_LENGTH) {
				log.warn("A Remote Provider application was parsed that has more than "
							+ RemoteProviderApplication.NATIVE_NAME_LENGTH
							+ " characters in it. The name is being trimmed but this"
							+ " should not prevent use of the application");
				app.setNativeName(app.getNativeName().substring(0, RemoteProviderApplication.NATIVE_NAME_LENGTH-1));
			}
			
			app.setRemoteProviderType(remoteProviderType);
		}
		
		return newApps;
	}
	
	@Override
	public void deleteApps(RemoteProviderType remoteProviderType) {
		if (remoteProviderType != null && remoteProviderType
				.getRemoteProviderApplications() != null) {
			log.info("Deleting apps for Remote Provider type " + remoteProviderType.getName() +
					" (id=" + remoteProviderType.getId() + ")");
			for (RemoteProviderApplication app : remoteProviderType
					.getRemoteProviderApplications()) {
				log.info("Deleting Remote Application " + app.getNativeName() +
						" (id = " + app.getId() + ", type id=" + remoteProviderType.getId() + ")");
				remoteProviderApplicationDao.delete(app);
			}
		}
	}

	@Override
	public String processApp(int remoteProviderApplicationId, int applicationId) {

		Application application = applicationDao.retrieveById(applicationId);

		if (application == null) {
			return "Application choice was invalid.";
		}

        RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationDao.retrieveById(remoteProviderApplicationId);

        if (remoteProviderApplication == null) {
            return "Unable to find that Remote Provider application in the database.";
        }

		List<RemoteProviderApplication> rpApps = application.getRemoteProviderApplications();
		for (RemoteProviderApplication rpa: rpApps ) {
			if (rpa.getRemoteProviderType().getId().equals(remoteProviderApplication.getRemoteProviderType().getId())) {
				return "Application already has a mapping for this Remote Provider Type. Please choose another application.";
			}
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
		
		return "";
	}
	
	@Override
	public List<RemoteProviderApplication> loadAllWithMappings() {
		return remoteProviderApplicationDao.retrieveAllWithMappings();
	}

	@Override
	public void addBulkImportToQueue(RemoteProviderType remoteProviderType) {
		if (remoteProviderType == null || remoteProviderType.getRemoteProviderApplications() == null ||
				remoteProviderType.getRemoteProviderApplications().isEmpty()) {
			log.error("Null remote provider type passed to addBulkImportToQueue. Something went wrong.");
			return;
		}
		
		if (remoteProviderType.getHasConfiguredApplications()) {
			log.info("At least one application is configured.");
			queueSender.addRemoteProviderImport(remoteProviderType);
		} else {
			log.error("No apps were configured with applications.");
		}
	}

	@Override
	public String deleteMapping(RemoteProviderApplication remoteProviderApplication,
			int appId) {

		Application application = applicationDao.retrieveById(appId);
		String returnStr = "";
		
		List<RemoteProviderApplication> rpAppList = application.getRemoteProviderApplications();
		if (rpAppList != null && !rpAppList.isEmpty()) {
			
			for (RemoteProviderApplication rpa: rpAppList) {
				if (rpa.getRemoteProviderType().getId().equals(
						remoteProviderApplication.getRemoteProviderType().getId())) {
					if (rpa.getApplicationChannel().getScanList() != null &&
							!rpa.getApplicationChannel().getScanList().isEmpty()) {
						returnStr = "But this application has Scans associated with the Remote Provider Application!";
					}
				}
			}
			
		}

		if (application.getRemoteProviderApplications() == null) {
			application.setRemoteProviderApplications(
					new ArrayList<RemoteProviderApplication>());
		}

		if (application.getRemoteProviderApplications().contains(remoteProviderApplication)) {
			application.getRemoteProviderApplications().remove(remoteProviderApplication);
			remoteProviderApplication.setApplication(null);
		}

		store(remoteProviderApplication);
		applicationDao.saveOrUpdate(application);

		return returnStr;
	}

    @Override
    public String setCustomName(int remoteProviderApplicationId, String customName) {

        RemoteProviderApplication applicationFromId = load(remoteProviderApplicationId);
        RemoteProviderApplication applicationFromName = remoteProviderApplicationDao.retrieveByCustomName(customName);

        if (applicationFromName != null) {
            if (applicationFromId.getId().equals(remoteProviderApplicationId)) {
                log.debug("The custom name was not changed, continuing");
            } else {
                return "That name was already taken.";
            }
        } else if (customName.length() > 100) {
            return "Maximum length is 100 characters.";
        } else {
            applicationFromId.setCustomName(customName);
            remoteProviderApplicationDao.saveOrUpdate(applicationFromId);
            log.info("Successfully updated name of remote provider application with native ID " +
                    applicationFromId.getNativeId() + " to name " + customName);
        }

        return "Success";
    }
}
