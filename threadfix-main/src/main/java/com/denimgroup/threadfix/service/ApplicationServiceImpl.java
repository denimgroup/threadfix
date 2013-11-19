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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.ApplicationCriticalityDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.dao.WafDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.webapp.controller.TableSortBean;

@Service
@Transactional(readOnly = false)
public class ApplicationServiceImpl implements ApplicationService {
	
	protected final SanitizedLogger log = new SanitizedLogger(ApplicationServiceImpl.class);
	
	private String invalidProjectName = "The selected Project Name was invalid. " +
			"Either a non-existent project or a project with no components was selected.";
	
	private String invalidCredentials = "The User / password combination " +
			"(or possibly the Defect Tracker endpoint URL)";

	private ApplicationDao applicationDao = null;
	private DefectTrackerDao defectTrackerDao = null;
	private RemoteProviderApplicationDao remoteProviderApplicationDao = null;
	private WafRuleDao wafRuleDao = null;
	private WafDao wafDao = null;
	private VulnerabilityDao vulnerabilityDao = null;
	private AccessControlMapService accessControlMapService;
	private ApplicationCriticalityDao applicationCriticalityDao = null;
	private DefectDao defectDao = null;
	private PermissionService permissionService = null;
	private ScanMergeService scanMergeService = null;
	private ScanQueueService scanQueueService;

	@Autowired
	public ApplicationServiceImpl(ApplicationDao applicationDao,
			DefectTrackerDao defectTrackerDao,
			RemoteProviderApplicationDao remoteProviderApplicationDao,
			PermissionService permissionService, WafRuleDao wafRuleDao,
			AccessControlMapService accessControlMapService,
			VulnerabilityDao vulnerabilityDao, WafDao wafDao,
			ApplicationCriticalityDao applicationCriticalityDao,
			DefectDao defectDao,
			ScanMergeService scanMergeService,
			ScanQueueService scanQueueService) {
		this.applicationDao = applicationDao;
		this.defectTrackerDao = defectTrackerDao;
		this.accessControlMapService = accessControlMapService;
		this.remoteProviderApplicationDao = remoteProviderApplicationDao;
		this.permissionService = permissionService;
		this.wafRuleDao = wafRuleDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.wafDao = wafDao;
		this.applicationCriticalityDao = applicationCriticalityDao;
		this.defectDao = defectDao;
		this.scanMergeService = scanMergeService;
		this.scanQueueService = scanQueueService;
	}

	@Override
	public List<Application> loadAllActive() {
		return applicationDao.retrieveAllActive();
	}
	
	@Override
	public List<Application> loadAllActiveFilter(Set<Integer> authenticatedTeamIds) {
		
		if (PermissionUtils.hasGlobalReadAccess()) {
			return loadAllActive();
		}
		
		if (authenticatedTeamIds == null || authenticatedTeamIds.size() == 0) {
			return new ArrayList<>();
		}
		
		return applicationDao.retrieveAllActiveFilter(authenticatedTeamIds);
	}
	
	@Override
	public Application loadApplication(int applicationId) {
		return applicationDao.retrieveById(applicationId);
	}

	@Override
	public Application loadApplication(String applicationName, int teamId) {
		return applicationDao.retrieveByName(applicationName, teamId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeApplication(Application application) {
		if (application != null) {
			applicationDao.saveOrUpdate(application);
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateApplication(Application application) {
		application.setActive(false);
		application.setModifiedDate(new Date());
		removeRemoteApplicationLinks(application);
		String possibleName = getNewName(application);
		
		if (application.getAccessControlApplicationMaps() != null) {
			for (AccessControlApplicationMap map : application.getAccessControlApplicationMaps()) {
				accessControlMapService.deactivate(map);
			}
		}
		
		if (application.getScanQueueTasks() != null) {
			for (ScanQueueTask task : application.getScanQueueTasks())
				scanQueueService.deactivateTask(task);
				
		}
		
		if (applicationDao.retrieveByName(possibleName, application.getOrganization().getId()) == null) {
			application.setName(possibleName);
		}
		applicationDao.saveOrUpdate(application);
	}
	
	private String getNewName(Application application) {
		if (application != null) {
			
			String testString = "deleted-" + application.getId() + "-" + application.getName();
			if (testString.length() > Application.NAME_LENGTH) {
				testString = testString.substring(0, Application.NAME_LENGTH - 2);
			}
			return testString;
		}
		return null;
	}
	
	private void removeRemoteApplicationLinks(Application application) {
		if (application.getRemoteProviderApplications() != null &&
				application.getRemoteProviderApplications().size() > 0) {
			log.info("Removing remote applications from the application " + application.getName() +
					 " (id=" + application.getId() + ")");
			for (RemoteProviderApplication app : application.getRemoteProviderApplications()) {
				log.info("Removing remote application " + app.getNativeId() +
						 " from application " + app.getApplication().getName());
				app.setApplication(null);
				app.setLastImportTime(null);
				app.setApplicationChannel(null);
				remoteProviderApplicationDao.saveOrUpdate(app);
			}
		}
	}
	
	@Override
	public boolean validateApplicationDefectTracker(Application application,
			BindingResult result) {
		if (application == null || result == null) {
			return false;
		}
		
		if (application.getDefectTracker() != null &&
				(application.getDefectTracker().getId() == null
				|| application.getDefectTracker().getId() == 0)) {
			application.setDefectTracker(null);
			application.setUserName(null);
			application.setPassword(null);
		} else if (application.getDefectTracker() != null){
			DefectTracker defectTracker = defectTrackerDao.retrieveById(
					application.getDefectTracker().getId());
			if (defectTracker == null) {
				result.rejectValue("defectTracker.id", "errors.invalid",
						new String [] { "Defect Tracker choice" }, null);
				application.setUserName(null);
				application.setPassword(null);
				application.setProjectName(null);
			} else {
				
				application.setDefectTracker(defectTracker);
				AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
				if (dt != null) {
					if (application.getUserName() == null
							|| application.getUserName().isEmpty()) {
						result.rejectValue("userName", "errors.required",
								new String [] { "User Name" }, null);
					}
					if (application.getPassword() == null
							|| application.getPassword().isEmpty()) {
						result.rejectValue("password", "errors.required",
								new String [] { "Password" }, null);
					}
					
					if (!result.hasErrors()) {
						if (!dt.hasValidCredentials()) {
							if (dt.getLastError() == null) {
								result.rejectValue("userName", "errors.invalid",
										new String [] { invalidCredentials }, null);
							} else {
								result.rejectValue("userName", "errors.detail",
										new String [] { dt.getLastError() }, null);
							}
							application.setUserName(null);
							application.setPassword(null);
							application.setProjectName(null);
						} else if (!dt.hasValidProjectName()) {
							result.rejectValue("projectName", "errors.detail",
									new String [] { invalidProjectName }, null);
							application.setProjectName(null);
						} else {
							encryptCredentials(application);
							application.setProjectId(dt.getProjectIdByName());
							return checkNewDefectTracker(application);
						}
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * 
	 * @param application
	 * @return true if the application has a different defect tracker
	 * 			than the database version, false otherwise
	 */
	private boolean checkNewDefectTracker(Application application) {
		if (application == null || application.getId() == null ||
				application.getDefectTracker() == null ||
				application.getDefectTracker().getId() == null) {
			return false;
		}
		
		Application databaseApplication = applicationDao.retrieveById(application.getId());
		
		if (databaseApplication == null || databaseApplication.getId() == null ||
				databaseApplication.getDefectTracker() == null ||
				databaseApplication.getDefectTracker().getId() == null) {
			return false;
		}
		
		return !application.getDefectTracker().getId().equals(
				databaseApplication.getDefectTracker().getId());
	}
	
	@Override
	public boolean checkApplication(Application application) {
		if (application == null || application.getName() == null
				|| application.getName().trim().isEmpty()
				|| application.getName().length() > Application.NAME_LENGTH) {
			log.warn("The application's name was invalid.");
			return false;
		}
		
		if (application.getUrl() != null &&
				application.getUrl().length() > Application.URL_LENGTH) {
			log.warn("The application's url was too long.");
			return false;
		}
		
		Application databaseApplication = loadApplication(application.getName().trim(), 
				application.getOrganization().getId());

		return databaseApplication == null;
	}
	
	@Override
	public void updateWafRules(Application application, Integer dbApplicationWafId) {
		if (application == null || application.getId() == null ||
				dbApplicationWafId == null) {
			return;
		}

		// if the new app doesn't have a WAF or the IDs don't match, need to remove the rules
		if (application.getWaf() == null ||
				application.getVulnerabilities() != null &&
				 application.getWaf().getId() != null &&
				 !dbApplicationWafId.equals(application.getWaf().getId())) {
			
			// Database vulns are still in session, also the vulns themselves
			// shouldn't have changed since we were only editing the information
			// about the Application object and not its vulnerabilities.
			for (Vulnerability vulnerability : application.getVulnerabilities()) {
				if (vulnerability != null && vulnerability.getWafRules() != null) {
					for (WafRule wafRule : vulnerability.getWafRules()) {
						wafRuleDao.delete(wafRule);
					}
					vulnerability.setWafRuleGeneratedTime(null);
					vulnerability.setWafRules(new ArrayList<WafRule>());
					vulnerabilityDao.saveOrUpdate(vulnerability);
				}
			}
		}
	}
	
	@Override
	public void validateAfterEdit(Application application, BindingResult result) {
		if (application.getName() != null && application.getName().trim().equals("")) {
			if (!result.hasFieldErrors("name")) {
				result.rejectValue("name", null, null, "This field cannot be blank");
			}
			return;
		}
		
		if (application.getRepositoryFolder() != null && !application.getRepositoryFolder().trim().equals("")) {
			File file = new File(application.getRepositoryFolder().trim());
			if (!file.exists() || !file.isDirectory()) {
				result.rejectValue("repositoryFolder", null, null, "Invalid directory");
				return;
			}
		}		
						
		Application databaseApplication = decryptCredentials(loadApplication(application.getName().trim(), application.getOrganization().getId()));

		if (application.getApplicationCriticality() == null ||
				application.getApplicationCriticality().getId() == null ||
				applicationCriticalityDao.retrieveById(
						application.getApplicationCriticality().getId()) == null) {
			result.rejectValue("applicationCriticality.id", "errors.invalid",
					new String [] { "Criticality" }, null);
		}
		
		boolean canManageWafs = false, canManageDefectTrackers = false;
		
		if (application.getOrganization() != null) {
			canManageWafs = permissionService.isAuthorized(Permission.CAN_MANAGE_WAFS,
					application.getOrganization().getId(), application.getId());
			
			canManageDefectTrackers = permissionService.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS,
					application.getOrganization().getId(), application.getId());
		}
		
		Application oldApp = loadApplication(application.getId());
		
		if (oldApp != null && !canManageWafs) {
			application.setWaf(oldApp.getWaf());
		}
		
		if (oldApp != null && !canManageDefectTrackers) {
			application.setDefectTracker(oldApp.getDefectTracker());
		}
		
		if (application.getWaf() != null && (application.getWaf().getId() == null ||
				application.getWaf().getId() == 0)) {
			application.setWaf(null);
		}
		
		if (application.getWaf() != null && application.getWaf().getId() != null) {
			Waf waf = wafDao.retrieveById(application.getWaf().getId());
			
			if (waf == null) {
				result.rejectValue("waf.id", "errors.invalid",
						new String [] { "WAF Choice" }, null);
			} else {
				application.setWaf(waf);
			}
		}
		
		// The password was set to the temp password so that it wouldn't show up on the page.
		// If the credentials haven't changed, re-decrypt the password to get the original.
		if (application.getPassword() != null && application.getPassword().equals(Application.TEMP_PASSWORD) &&
				databaseApplication != null && databaseApplication.getUserName() != null &&
				databaseApplication.getUserName().equals(application.getUserName()) &&
				databaseApplication.getDefectTracker() != null &&
				application.getDefectTracker() != null &&
				databaseApplication.getDefectTracker().getId().equals(
						application.getDefectTracker().getId())) {
			decryptCredentials(application);
		}
			
		if (databaseApplication != null && !databaseApplication.getId().equals(
				application.getId())) {
			result.rejectValue("name", "errors.nameTaken");
		}
		
		Integer databaseWafId = null;
		if (databaseApplication != null && databaseApplication.getWaf() != null) {
			databaseWafId = databaseApplication.getWaf().getId();
		}
		
		// remove any outdated vuln -> waf rule links
		updateWafRules(loadApplication(application.getId()), databaseWafId);
	}
	
	@Override
	public void validateDefectTracker(Application application, BindingResult result) {
		boolean hasNewDefectTracker = validateApplicationDefectTracker(application, result);
		
		if (hasNewDefectTracker || application.getDefectTracker() == null
				&& application.getDefectList() != null) {
			defectDao.deleteByApplicationId(application.getId());
			
			List<Vulnerability> vulns = applicationDao.getVulns(application);
			
			if (vulns != null) {
				for (Vulnerability vuln : vulns) {
					vuln.setDefect(null);
					vulnerabilityDao.saveOrUpdate(vuln);
				}
			}
		}
	}
	
	@Override
	public void updateProjectRoot(Application application) {
		if (application != null && application.getProjectRoot() != null
				&& !application.getProjectRoot().trim().equals("")) {
			Application app = loadApplication(application.getId());
			
			scanMergeService.updateSurfaceLocation(app);
			scanMergeService.updateVulnerabilities(app);
							
			storeApplication(app);
		}
	}
	
	@Override
	public void validateAfterCreate(Application application, BindingResult result) {
		
		if (application.getName() == null || application.getName().trim().equals("")) {
			
			if (!result.hasFieldErrors("name")) {
				result.rejectValue("name", null, null, "This field cannot be blank");
			}
			return;
		}
		
		if (application.getApplicationCriticality() == null ||
				application.getApplicationCriticality().getId() == null ||
				applicationCriticalityDao.retrieveById(
						application.getApplicationCriticality().getId()) == null) {
			result.rejectValue("applicationCriticality.id", "errors.invalid",
					new String [] { "Criticality" }, null);
		}
		
		boolean canManageWafs = false, canManageDefectTrackers = false;
		
		if (application.getOrganization() != null) {
			canManageWafs = permissionService.isAuthorized(Permission.CAN_MANAGE_WAFS,
					application.getOrganization().getId(), application.getId());
			
			canManageDefectTrackers = permissionService.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS,
					application.getOrganization().getId(), application.getId());
		}
		
		Application databaseApplication = loadApplication(application.getName().trim(), application.getOrganization().getId());
		if (databaseApplication != null) {
			result.rejectValue("name", "errors.nameTaken");
			return;
		}
		
		if (application.getRepositoryFolder() != null && !application.getRepositoryFolder().trim().equals("")) {
			File file = new File(application.getRepositoryFolder().trim());
			if (!file.exists() || !file.isDirectory()) {
				result.rejectValue("repositoryFolder", null, null, "Invalid directory");
				return;
			}
		}
		
		if (!canManageWafs && application.getWaf() != null) {
			application.setWaf(null);
		}
		
		if (!canManageDefectTrackers && application.getDefectTracker() != null) {
			application.setDefectTracker(null);
		}

		if (application.getWaf() != null && application.getWaf().getId() == 0) {
			application.setWaf(null);
		}
		
		if (application.getWaf() != null && (application.getWaf().getId() == null
				|| wafDao.retrieveById(application.getWaf().getId()) == null)) {
			result.rejectValue("waf.id", "errors.invalid",
					new String [] { "WAF Choice" }, null);
		}

		validateApplicationDefectTracker(application, result);
	}

	@Override
	public List<Vulnerability> getVulnTable(int appId, TableSortBean bean) {
		if (bean != null) {
			int page = bean.getPage();
			int sort = bean.getSort();
			int field = bean.getField();
			
			String description = null, severity = null, path = null, param = null;
						
			if (bean.getDescriptionFilter() != null && !bean.getDescriptionFilter().trim().equals("")) {
				description = bean.getDescriptionFilter().trim();
			}
			
			if (bean.getSeverityFilter() != null && !bean.getSeverityFilter().trim().equals("")) {
				severity = bean.getSeverityFilter().trim();
			}
			
			if (bean.getLocationFilter() != null && !bean.getLocationFilter().trim().equals("")) {
				path = bean.getLocationFilter().trim();
			}
			
			if (bean.getParameterFilter() != null && !bean.getParameterFilter().trim().equals("")) {
				param = bean.getParameterFilter().trim();
			}
					
			Integer cweInteger = getCweId(bean);
			
			return vulnerabilityDao.retrieveActiveByAppIdAndPage(appId, page, sort, field, cweInteger,
										description, severity, path, param, bean.isOpen(),
										bean.isFalsePositive(), bean.isHidden());
		} else {
			return vulnerabilityDao.retrieveActiveByAppIdAndPage(appId, 1, 0, 0, null, null, null, null,
					null, true, false, false);
		}
	}
	
	private Integer getCweId(TableSortBean bean) {
		if (bean.getCweFilter() != null && !bean.getCweFilter().trim().equals("")) {
			String cwe = bean.getCweFilter().trim();
			
			try {
				return Integer.valueOf(cwe);
			} catch (NumberFormatException e) {
				log.warn("Invalid string submitted for CWE ID.", e);
			}
		}
		
		return null;
	}
	
	@Override
	public long getCount(Integer appId, TableSortBean bean) {
		String description = null, severity = null, path = null, param = null;
		
		if (bean.getDescriptionFilter() != null && !bean.getDescriptionFilter().trim().equals("")) {
			description = bean.getDescriptionFilter().trim();
		}
		
		if (bean.getSeverityFilter() != null && !bean.getSeverityFilter().trim().equals("")) {
			severity = bean.getSeverityFilter().trim();
		}
		
		if (bean.getLocationFilter() != null && !bean.getLocationFilter().trim().equals("")) {
			path = bean.getLocationFilter().trim();
		}
		
		if (bean.getParameterFilter() != null && !bean.getParameterFilter().trim().equals("")) {
			param = bean.getParameterFilter().trim();
		}
		
		Integer cweInteger = getCweId(bean);
		
		return vulnerabilityDao.getVulnCountWithFilters(appId,description,severity,path,param, cweInteger,
														bean.isOpen(), bean.isFalsePositive(), bean.isHidden());
	}
	
	@Override
	public long getVulnCount(Integer appId, boolean open) {
		return vulnerabilityDao.getVulnCount(appId, open);
	}
	
	public Application encryptCredentials(Application application) {
		try {
			if (application != null && application.getPassword() != null && application.getPassword() != null) {
				application.setEncryptedPassword(ESAPI.encryptor().encrypt(application.getPassword()));
				application.setEncryptedUserName(ESAPI.encryptor().encrypt(application.getUserName()));
			}
		} catch (EncryptionException e) {
			log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
		}
		return application;
	}
	
	@Override
	public Application decryptCredentials(Application application) {
		try {
			if (application != null && application.getEncryptedPassword() != null &&
					application.getEncryptedUserName() != null) {
				application.setPassword(ESAPI.encryptor().decrypt(application.getEncryptedPassword()));
				application.setUserName(ESAPI.encryptor().decrypt(application.getEncryptedUserName()));
			}
		} catch (EncryptionException e) {
			log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
		}
		return application;
	}

	@Override
	public void generateVulnerabilityReports(List<Organization> organizations) {
		if (organizations == null) {
			return;
		}
		for (Organization org : organizations) {
			generateVulnerabilityReports(org);
		}
	}
	
	@Override
	public void generateVulnerabilityReports(Organization organization) {
		if (organization == null || organization.getActiveApplications() == null) {
			return;
		}
		
		for (Application app : organization.getActiveApplications()) {
			generateVulnerabilityReport(app);
		}
	}
	
	public void generateVulnerabilityReport(Application application) {
		application.setVulnerabilityReport(applicationDao.loadVulnerabilityReport(application));
	}
}
