////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
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
	
	private final SanitizedLogger log = new SanitizedLogger(RemoteProviderTypeServiceImpl.class);
	
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
		List<RemoteProviderType> remoteProviderList = remoteProviderTypeDao.retrieveAll();
		
		if (remoteProviderList != null && remoteProviderList.size() > 0) {
			for (RemoteProviderType type : remoteProviderList) {
				decryptCredentials(type);
			}
		}
		
		return remoteProviderList;
	}

	@Override
	public RemoteProviderType load(String name) {
		return decryptCredentials(remoteProviderTypeDao.retrieveByName(name));
	}

	@Override
	public RemoteProviderType load(int id) {
		return decryptCredentials(remoteProviderTypeDao.retrieveById(id));
	}
	
	/**
	 * Put the unencrypted credentials back into the object.
	 * @param type
	 * @return
	 */
	private RemoteProviderType encryptCredentials(RemoteProviderType type) {
		try {
			if (type != null && type.getHasApiKey() && type.getApiKey() != null) {
				type.setEncryptedApiKey(ESAPI.encryptor().encrypt(type.getApiKey()));
			} else if (type != null && type.getHasUserNamePassword() && 
					type.getUsername() != null && type.getPassword() != null) {
				type.setEncryptedUsername(ESAPI.encryptor().encrypt(type.getUsername()));
				type.setEncryptedPassword(ESAPI.encryptor().encrypt(type.getPassword()));
			}
		} catch (EncryptionException e) {
			log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
		}
		
		return type;
	}
	
	/**
	 * Move the unencrypted credentials in the transient fields into the 
	 * encrypted fields that will be saved.
	 * @param type
	 * @return
	 */
	@Override
	public RemoteProviderType decryptCredentials(RemoteProviderType type) {
		try {
			if (type != null && type.getHasApiKey() && type.getEncryptedApiKey() != null) {
				type.setApiKey(ESAPI.encryptor().decrypt(type.getEncryptedApiKey()));
			} else if (type != null && type.getHasUserNamePassword() && 
					type.getEncryptedUsername() != null && type.getEncryptedPassword() != null) {
				type.setUsername(ESAPI.encryptor().decrypt(type.getEncryptedUsername()));
				type.setPassword(ESAPI.encryptor().decrypt(type.getEncryptedPassword()));
			}
		} catch (EncryptionException e) {
			log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
		}
		
		return type;
	}

	@Override
	public void store(RemoteProviderType remoteProviderType) {
		remoteProviderTypeDao.saveOrUpdate(remoteProviderType);
	}
	
	@Override
	public void checkConfiguration(RemoteProviderType remoteProviderType, 
			BindingResult result, int typeId) {
		RemoteProviderType databaseRemoteProviderType = decryptCredentials(load(typeId));
				
		if (remoteProviderType != null &&
				remoteProviderType.getPassword() != null &&
				remoteProviderType.getPassword().equals(USE_OLD_PASSWORD) &&
				databaseRemoteProviderType != null &&
				databaseRemoteProviderType.getPassword() != null) {
			remoteProviderType.setPassword(databaseRemoteProviderType.getPassword());
		}
		
		if (remoteProviderType != null &&
				remoteProviderType.getApiKey() != null &&
				remoteProviderType.getApiKey().startsWith(USE_OLD_PASSWORD) &&
				databaseRemoteProviderType != null &&
				databaseRemoteProviderType.getApiKey() != null) {
			remoteProviderType.setApiKey(databaseRemoteProviderType.getApiKey());
		}
		
		// If the username hasn't changed but the password has, update the apps instead of deleting them.
		
		if (databaseRemoteProviderType != null &&
				remoteProviderType != null && remoteProviderType.getUsername() != null &&
				remoteProviderType.getUsername().equals(databaseRemoteProviderType.getUsername()) &&
				remoteProviderType != null && remoteProviderType.getPassword() != null &&
				!remoteProviderType.getPassword().equals(databaseRemoteProviderType.getPassword())) {
			
			log.warn("Provider password has changed, updating applications.");
			
			remoteProviderApplicationService.updateApplications(remoteProviderType);
			
		} else if (databaseRemoteProviderType == null || 
				(remoteProviderType != null && remoteProviderType.getUsername() != null &&
				!remoteProviderType.getUsername().equals(databaseRemoteProviderType.getUsername())) ||
				(remoteProviderType != null && remoteProviderType.getApiKey() != null &&
				!remoteProviderType.getApiKey().equals(
						databaseRemoteProviderType.getApiKey()))) {
		
			List<RemoteProviderApplication> apps = remoteProviderApplicationService
													.getApplications(remoteProviderType);
			
			if (apps == null) {
				// Here the apps coming back were null. For now let's put an error page.
				// TODO finalize this process.
				String field = null;
				if (remoteProviderType.getHasApiKey()) {
					field = "apiKey";
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
								
				store(encryptCredentials(remoteProviderType));
			}
		} else {
			log.info("No change was made to the credentials.");
		}
	}

	@Override
	public void clearConfiguration(int id) {
		RemoteProviderType type = load(id);
		
		if (type != null) {
			type.setEncrypted(false);
			type.setEncryptedApiKey(null);
			type.setEncryptedUsername(null);
			type.setEncryptedPassword(null);
			if (type.getRemoteProviderApplications() != null) {
				remoteProviderApplicationService.deleteApps(type);
			}
			
			store(type);
		}
	}
}
