////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.RemoteProviderTypeDao;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderAuthenticationField;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Transactional(readOnly = false)
public class RemoteProviderTypeServiceImpl implements RemoteProviderTypeService {

    private static final SanitizedLogger LOG = new SanitizedLogger(RemoteProviderTypeServiceImpl.class);

    @Autowired
    private RemoteProviderTypeDao remoteProviderTypeDao;
    @Autowired
    private RemoteProviderApplicationService remoteProviderApplicationService;
    @Autowired
    private ScanMergeService scanMergeService;
    @Autowired
    private RemoteProviderFactory remoteProviderFactory;
    @Autowired
    private VulnerabilityService vulnerabilityService;

	@Override
	@Transactional
	public ResponseCode importScansForApplications(Integer remoteProviderTypeId) {

		RemoteProviderType type = load(remoteProviderTypeId);

		if (type == null) {
			LOG.error("Type was null, Remote Provider import failed.");
			return ResponseCode.BAD_ID;
		} else {

			decryptCredentials(type);

			List<RemoteProviderApplication> applications = type.getRemoteProviderApplications();

			if (applications == null || applications.isEmpty()) {
                LOG.error("No applications found, Remote Provider import failed.");
				return ResponseCode.NO_APPS;
			} else {

                LOG.info("Starting scan import for " + applications.size() + " applications.");

				for (RemoteProviderApplication application : applications) {
					if (application != null && application.getApplicationChannel() != null) {
						ResponseCode success = importScansForApplication(application);

						if (!success.equals(ResponseCode.SUCCESS)) {
                            LOG.info("No scans were imported for Remote Provider application " + application.getNativeName());
						} else {
                            LOG.info("Remote Provider import was successful for application " + application.getNativeName());
						}
					}
				}

				return ResponseCode.SUCCESS;
			}
		}

	}

	@Transactional(readOnly=false)
	@Override
	public ResponseCode updateAll() {
        LOG.info("Importing scans for all Remote Provider Applications.");
		List<RemoteProviderApplication> apps = remoteProviderApplicationService.loadAllWithMappings();

		if (apps == null || apps.size() == 0) {
            LOG.info("No apps with mappings found. Exiting.");
			return ResponseCode.NO_APPS;
		}

		for (RemoteProviderApplication remoteProviderApplication : apps) {
			if (remoteProviderApplication == null || remoteProviderApplication.getRemoteProviderType() == null) {
				continue;
			}
			decryptCredentials(remoteProviderApplication.getRemoteProviderType());
			importScansForApplication(remoteProviderApplication);
		}
		
		LOG.info("Completed requests for scan imports.");
		
		return ResponseCode.SUCCESS;
	}
	
	@Override
	public ResponseCode importScansForApplication(RemoteProviderApplication remoteProviderApplication) {
		
		if (remoteProviderApplication == null) {
			return ResponseCode.ERROR_OTHER;
		}
		
		List<Scan> resultScans = remoteProviderFactory.fetchScans(remoteProviderApplication);
		
		ResponseCode success = ResponseCode.ERROR_NO_SCANS_FOUND;
		if (resultScans != null && resultScans.size() > 0) {
			Collections.sort(resultScans, new Comparator<Scan>() {
				@Override
				public int compare(Scan scan1, Scan scan2){
					Calendar scan1Time = scan1.getImportTime();
					Calendar scan2Time = scan2.getImportTime();
					
					if (scan1Time == null || scan2Time == null) {
						return 0;
					}
					
					return scan1Time.compareTo(scan2Time);
				}
			});
			
			int noOfScanNotFound = 0;
			int noOfNoNewScans = 0;
			for (Scan resultScan : resultScans) {
				if (resultScan == null || resultScan.getFindings() == null) {
					LOG.warn("Remote Scan import returned a null scan.");
					noOfScanNotFound++;
					
				} else if (remoteProviderApplication.getLastImportTime() != null &&
							(resultScan.getImportTime() == null ||
							!remoteProviderApplication.getLastImportTime().before(
									resultScan.getImportTime()))) {
					LOG.warn("Remote Scan was not newer than the last imported scan " +
                            "for this RemoteProviderApplication.");
					noOfNoNewScans++;

				} else {
					LOG.info("Scan was parsed and has findings, passing to ScanMergeService.");
					
					remoteProviderApplication.setLastImportTime(resultScan.getImportTime());
					
					remoteProviderApplicationService.store(remoteProviderApplication);
					
					if (resultScan.getApplicationChannel() == null) {
						if (remoteProviderApplication.getApplicationChannel() != null) {
							resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
						} else {
							LOG.error("Didn't have enough application channel information.");
						}
					}
					
					if (resultScan.getApplicationChannel() != null) {
						if (resultScan.getApplicationChannel().getScanList() == null) {
							resultScan.getApplicationChannel().setScanList(new ArrayList<Scan>());
						}
						
						if (!resultScan.getApplicationChannel().getScanList().contains(resultScan)) {
							resultScan.getApplicationChannel().getScanList().add(resultScan);
						}
					
						scanMergeService.processRemoteScan(resultScan);
						success = ResponseCode.SUCCESS;

                        vulnerabilityService.updateVulnerabilityReport(remoteProviderApplication.getApplication());
					}
				}
			}
			
			if (!success.equals(ResponseCode.SUCCESS)) {
				if (noOfNoNewScans > 0) {
					success = ResponseCode.ERROR_NO_NEW_SCANS;
				} else if (noOfScanNotFound > 0) {
					success = ResponseCode.ERROR_NO_SCANS_FOUND;
				}
			}
		}

		return success;
	}

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
			if (type != null && type.getAuthenticationFields() != null) {
				for (RemoteProviderAuthenticationField field: type.getAuthenticationFields()) {
					if (field.isSecret()) {
						field.setEncryptedValue(ESAPI.encryptor().encrypt(field.getValue()));
						field.setValue(null);
					}
				}
			}
		} catch (EncryptionException e) {
			LOG.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
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

			if (type != null && type.getAuthenticationFields() != null) {
				for (RemoteProviderAuthenticationField field: type.getAuthenticationFields()) {
					if (field.isSecret() && field.getEncryptedValue() != null)
					field.setValue(ESAPI.encryptor().decrypt(field.getEncryptedValue()));
				}
			}
		} catch (EncryptionException e) {
			LOG.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
		}
		
		return type;
	}

	@Override
	public void store(RemoteProviderType remoteProviderType) {
		remoteProviderTypeDao.saveOrUpdate(remoteProviderType);
	}
	
	@Override
	public ResponseCode checkConfiguration(String username, String password, String apiKey, String matchSourceNumber,
                                           String platform, Map<String, String> authenticationFieldMap, int typeId) {
		
		RemoteProviderType databaseRemoteProviderType = load(typeId);

        boolean matchSourceNumberBoolean = "true".equals(matchSourceNumber);

		if (databaseRemoteProviderType == null) {
			return ResponseCode.BAD_ID;
		}
		
		databaseRemoteProviderType = decryptCredentials(databaseRemoteProviderType);
		
		// TODO test this
		// If the username hasn't changed but the password has, update the apps instead of deleting them.

        if (!databaseRemoteProviderType.getAuthenticationFields().isEmpty()) {

            return processAuthenticationFields(databaseRemoteProviderType, authenticationFieldMap);

        } else if (databaseRemoteProviderType.getHasUserNamePassword()) {

            return processUsernamePassword(username, password, platform, databaseRemoteProviderType, matchSourceNumberBoolean);
			
		} else if (databaseRemoteProviderType.getHasApiKey()) {

            return processApikey(username, password, apiKey, platform, databaseRemoteProviderType, matchSourceNumberBoolean);

		} else if (databaseRemoteProviderType.getMatchSourceNumbers() == null ||
                databaseRemoteProviderType.getMatchSourceNumbers() != matchSourceNumberBoolean) {

            databaseRemoteProviderType.setMatchSourceNumbers(matchSourceNumberBoolean);
            store(databaseRemoteProviderType);
            return ResponseCode.SUCCESS;

        } else {
			LOG.info("No change was made to the credentials.");
			return ResponseCode.SUCCESS;
		}
	}

    private ResponseCode processAuthenticationFields(RemoteProviderType databaseRemoteProviderType,
                                                     Map<String, String> authenticationFieldMap) {

        boolean updated = false;

        for (RemoteProviderAuthenticationField field : databaseRemoteProviderType.getAuthenticationFields()) {
            if (authenticationFieldMap.containsKey(field.getName())) {
                String value = authenticationFieldMap.get(field.getName());

                if (!value.equals(MASKED_VALUE) && !value.equals(field.getValue())) {
                    field.setValue(value);
                    updated = true;
                }
            }
        }

        if (updated) {
            LOG.info("Credentials have been updated, updating applications");

            List<RemoteProviderApplication> applications = remoteProviderApplicationService.updateApplications(databaseRemoteProviderType);

			encryptCredentials(databaseRemoteProviderType);

			store(databaseRemoteProviderType); // should cascade field values too

            if (applications != null && !applications.isEmpty()) {
                return ResponseCode.SUCCESS;
            } else {
                return ResponseCode.NO_APPS;
            }

        } else {
            LOG.info("No change to credentials.");
            return ResponseCode.SUCCESS;
        }
    }

    private ResponseCode processApikey(String username,
                                       String password,
                                       String apiKey,
                                       String platform,
                                       RemoteProviderType databaseRemoteProviderType,
                                       boolean matchSourceNumberBoolean) {

        if (databaseRemoteProviderType.getHasApiKey() &&
                apiKey != null &&
				!apiKey.startsWith(USE_OLD_PASSWORD) &&
				!apiKey.startsWith(MASKED_VALUE) &&
                !apiKey.equals(databaseRemoteProviderType.getApiKey())
                ||
                databaseRemoteProviderType.getHasUserNamePassword() &&
                        username != null &&
                        !username.equals(databaseRemoteProviderType.getUsername())) {

            LOG.warn("New API key, deleting old apps.");

            return importApplications(username, password, apiKey, platform, databaseRemoteProviderType, matchSourceNumberBoolean);
        } else {
            LOG.debug("No change to API key, returning success.");
            return ResponseCode.SUCCESS;
        }
    }

    private ResponseCode importApplications(String username, String password, String apiKey, String platform, RemoteProviderType databaseRemoteProviderType, boolean matchSourceNumberBoolean) {
        databaseRemoteProviderType.setApiKey(apiKey);
        databaseRemoteProviderType.setUsername(username);
        databaseRemoteProviderType.setPassword(password);
        databaseRemoteProviderType.setPlatform(platform);
        databaseRemoteProviderType.setMatchSourceNumbers(matchSourceNumberBoolean);

        List<RemoteProviderApplication> apps = remoteProviderApplicationService
                .getApplications(databaseRemoteProviderType);

        if (apps == null) {

            LOG.info("No applications were found for " + databaseRemoteProviderType.getName());
            return ResponseCode.NO_APPS;

        } else {

            remoteProviderApplicationService.deleteApps(databaseRemoteProviderType);

            databaseRemoteProviderType.setRemoteProviderApplications(apps);

            for (RemoteProviderApplication remoteProviderApplication :
                    databaseRemoteProviderType.getRemoteProviderApplications()) {
                remoteProviderApplicationService.store(remoteProviderApplication);
            }

            store(encryptCredentials(databaseRemoteProviderType));

            LOG.info("Successfully updated applications for " + databaseRemoteProviderType.getName());

            return ResponseCode.SUCCESS;
        }
    }

    private ResponseCode processUsernamePassword(String username,
                                                 String password,
                                                 String platform,
                                                 RemoteProviderType databaseRemoteProviderType,
                                                 boolean matchSourceNumberBoolean) {
        if (username != null && password != null) {

            if (databaseRemoteProviderType.getUsername() == null ||
                    !databaseRemoteProviderType.getUsername().equals(username)) {

                LOG.info("Importing applications for " + databaseRemoteProviderType.getName());

                return importApplications(username, password, "", platform, databaseRemoteProviderType, matchSourceNumberBoolean);

            } else if (username.equals(databaseRemoteProviderType.getUsername()) &&
                    !password.equals(USE_OLD_PASSWORD) &&
                    !password.equals(MASKED_VALUE) &&
                    !password.equals(databaseRemoteProviderType.getPassword())) {
                LOG.info("Provider password has changed, updating applications.");

                databaseRemoteProviderType.setPassword(password);
                databaseRemoteProviderType.setPlatform(platform);
                databaseRemoteProviderType.setMatchSourceNumbers(matchSourceNumberBoolean);
                remoteProviderApplicationService.updateApplications(databaseRemoteProviderType);
                store(databaseRemoteProviderType);
            }
        }
        return ResponseCode.SUCCESS;
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

            for (RemoteProviderAuthenticationField field : type.getAuthenticationFields()) {
                field.setValue(null);
				field.setEncryptedValue(null);
            }

            store(type);
		}
	}
}
