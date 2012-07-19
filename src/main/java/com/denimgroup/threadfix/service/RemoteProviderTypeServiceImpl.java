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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.RemoteProviderTypeDao;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;

@Service
@Transactional(readOnly = false)
public class RemoteProviderTypeServiceImpl implements RemoteProviderTypeService {
	
	private final Log log = LogFactory.getLog(RemoteProviderTypeServiceImpl.class);
	
	@Autowired
	public RemoteProviderTypeServiceImpl(RemoteProviderTypeDao remoteProviderTypeDao,
			RemoteProviderApplicationService remoteProviderApplicationService) {
		this.remoteProviderTypeDao = remoteProviderTypeDao;
		this.remoteProviderApplicationService = remoteProviderApplicationService;
	}
	
	private RemoteProviderTypeDao remoteProviderTypeDao;
	private RemoteProviderApplicationService remoteProviderApplicationService;

	@Override
	public List<RemoteProviderType> loadAll() {
		return remoteProviderTypeDao.retrieveAll();
	}

	@Override
	public RemoteProviderType load(String name) {
		return remoteProviderTypeDao.retrieveByName(name);
	}

	@Override
	public RemoteProviderType load(int id) {
		return remoteProviderTypeDao.retrieveById(id);
	}

	@Override
	public void store(RemoteProviderType remoteProviderType) {
		remoteProviderTypeDao.saveOrUpdate(remoteProviderType);
	}
	
	@Override
	public void checkConfiguration(RemoteProviderType remoteProviderType, 
			BindingResult result, int typeId) {
		RemoteProviderType databaseRemoteProviderType = load(typeId);
				
		if (remoteProviderType != null &&
				remoteProviderType.getPassword() != null &&
				remoteProviderType.getPassword().equals(USE_OLD_PASSWORD) &&
				databaseRemoteProviderType != null &&
				databaseRemoteProviderType.getPassword() != null) {
			remoteProviderType.setPassword(databaseRemoteProviderType.getPassword());
		}
		
		if (remoteProviderType != null &&
				remoteProviderType.getApiKeyString() != null &&
				remoteProviderType.getApiKeyString().startsWith(USE_OLD_PASSWORD) &&
				databaseRemoteProviderType != null &&
				databaseRemoteProviderType.getApiKeyString() != null) {
			remoteProviderType.setApiKeyString(databaseRemoteProviderType.getApiKeyString());
		}
		
		if (databaseRemoteProviderType == null || 
				(remoteProviderType != null && remoteProviderType.getUsername() != null &&
				!remoteProviderType.getUsername().equals(databaseRemoteProviderType.getUsername())) ||
				(remoteProviderType != null && remoteProviderType.getPassword() != null &&
				!remoteProviderType.getPassword().equals(databaseRemoteProviderType.getPassword())) ||
				(remoteProviderType != null && remoteProviderType.getApiKeyString() != null &&
				!remoteProviderType.getApiKeyString().equals(
						databaseRemoteProviderType.getApiKeyString()))) {
		
			List<RemoteProviderApplication> apps = remoteProviderApplicationService
													.getApplications(remoteProviderType);
			
			if (apps == null) {
				// Here the apps coming back were null. For now let's put an error page.
				// TODO finalize this process.
				String field = null;
				if (remoteProviderType.getHasApiKey()) {
					field = "apiKeyString";
				} else {
					field = "username";
				}
				
				result.rejectValue(field, "errors.other", 
						"We were unable to connect to the provider with these credentials.");
				
			} else {
				
				log.warn("Provider username has changed, deleting old apps.");
				
				remoteProviderApplicationService.deleteApps(databaseRemoteProviderType);

				remoteProviderType.setRemoteProviderApplications(apps);
				
				if (remoteProviderType.getRemoteProviderApplications() != null) {
					for (RemoteProviderApplication remoteProviderApplication : 
							remoteProviderType.getRemoteProviderApplications()) {
						remoteProviderApplicationService.store(remoteProviderApplication);
					}
				}
				
				store(remoteProviderType);
			}
		} else {
			log.info("No change was made to the credentials.");
		}
	}

	@Override
	public void clearConfiguration(int id) {
		RemoteProviderType type = load(id);
		
		if (type != null) {
			type.setApiKeyString(null);
			type.setUsername(null);
			type.setPassword(null);
			if (type.getRemoteProviderApplications() != null) {
				remoteProviderApplicationService.deleteApps(type);
			}
			
			store(type);
		}
	}
}
