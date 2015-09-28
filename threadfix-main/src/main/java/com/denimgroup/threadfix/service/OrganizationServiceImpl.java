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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.importer.util.IntegerUtils.getIntegerOrNull;

@Service
@Transactional(readOnly = false) // used to be true
public class OrganizationServiceImpl extends AbstractNamedObjectService<Organization> implements OrganizationService {
	
	protected final SanitizedLogger log = new SanitizedLogger(OrganizationService.class);

    @Autowired
	private OrganizationDao organizationDao = null;
    @Autowired
	private ApplicationService applicationService = null;
    @Autowired(required = false)
    @Nullable
	private PermissionService permissionService = null;
    @Autowired
	private AccessControlMapService accessControlMapService = null;
    @Autowired
    private ApplicationDao applicationDao;
    @Autowired
    private ScheduledEmailReportService scheduledEmailReportService;

	@Override
	@Transactional(readOnly = false)
	public void markInactive(Organization organization) {
		log.warn("Deleting organization with ID " + organization.getId());
		
		organization.setActive(false);
		
		organization.setName("deleted-" + organization.getId() + "-" + organization.getName());
		if (organization.getName().length() >= Organization.NAME_LENGTH) {
			organization.setName(organization.getName().substring(0, Organization.NAME_LENGTH - 2));
		}
		
		organization.setModifiedDate(new Date());
		
		if (organization.getActiveApplications() != null) {
			for (Application app : organization.getActiveApplications()) {
				applicationService.deactivateApplication(app);
			}
		}
		
		if (organization.getAccessControlTeamMaps() != null) {
			for (AccessControlTeamMap map : organization.getAccessControlTeamMaps()) {
				accessControlMapService.deactivate(map);
			}
		}

        // Delete this team from all ScheduledEmailReport records
        if (organization.getScheduledEmailReports() != null) {
            for (ScheduledEmailReport scheduledEmailReport : organization.getScheduledEmailReports()) {
                scheduledEmailReportService.removeTeam(scheduledEmailReport, organization);
            }
        }

		organizationDao.saveOrUpdate(organization);
	}
	
	// TODO make this better
	public boolean isValidOrganization(Organization organization) {

		return organization != null && organization.getName() != null 
				&& !organization.getName().trim().isEmpty() 
				&& organization.getName().length() < Organization.NAME_LENGTH
				&& loadByName(organization.getName()) == null;
	}
	
	@Override
	public List<Organization> loadAllActiveFilter() {

        return loadTeams(Permission.READ_ACCESS, true);

	}

    @Override
    public List<Organization> loadTeams(Permission permission, boolean checkApps) {
        if (!EnterpriseTest.isEnterprise() || PermissionUtils.hasGlobalPermission(permission))
            return loadAllActive();

        if (permissionService == null) {
            throw new IllegalStateException("EnterpriseTest.isEnterprise returned true but permissionService is null. " +
                    "Fix the code.");
        }

        Set<Integer> ids = permissionService.getAuthenticatedTeamIds();

        Set<Integer> teamIds;

        if (ids == null || ids.isEmpty()) {
            teamIds = new HashSet<>();
        } else {
            teamIds = new HashSet<>(ids);
        }

        if (checkApps) {
            // Also add in the teams that only have app permissions
            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            if (appIds != null && !appIds.isEmpty()) {
                for (Integer id : appIds) {
                    Application app = applicationService.loadApplication(id);
                    if (app != null && app.getOrganization() != null &&
                            app.getOrganization().getId() != null &&
                            !teamIds.contains(app.getOrganization().getId())) {
                        teamIds.add(app.getOrganization().getId());
                    }
                }
            }
        }

        if (teamIds.size() == 0) {
            return list();
        }

        List<Organization> tempList = organizationDao.retrieveAllActiveFilter(teamIds);
        if (permission == Permission.READ_ACCESS)
            return tempList;
        else {
            List<Organization> returnList = list();
            for (Organization org: tempList) {
                if (permissionService.isAuthorized(permission, org.getId(), null))
                    returnList.add(org);
            }
            return returnList;
        }
    }

    @Override
    public List<Application> search(Integer orgId, HttpServletRequest request) {
        String searchString = request.getParameter("searchString");
        if (searchString == null) {
            searchString = "";
        }
        Long count = applicationDao.countApps(orgId, searchString);

        Integer page = getIntegerOrNull(request.getParameter("page")),
                number = getIntegerOrNull(request.getParameter("number"));

        if (page == null || page < 1) {
            page = 1;
        }

        if (number == null || number < 1) {
            number = 1;
        }

        if ((page - 1) * number > count) {
            page = 1;
        }


        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return applicationDao.getSearchResults(orgId, searchString, number, page, null, null);
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return applicationDao.getSearchResults(orgId, searchString, number, page, appIds, teamIds);
        } else {
            return applicationDao.getSearchResults(orgId, searchString, number, page, null, null);
        }
    }

    @Override
    public Long countApps(Integer orgId, String searchString) {

        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return applicationDao.countApps(orgId, searchString);
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return applicationDao.countApps(orgId, searchString, appIds, teamIds);
        } else {
            return applicationDao.countApps(orgId, searchString);
        }

    }

    @Override
    public Long countVulns(Integer orgId) {
        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return applicationDao.countVulns(orgId, null, null);
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return applicationDao.countVulns(orgId, appIds, teamIds);
        } else {
            return applicationDao.countVulns(orgId, null, null);
        }
    }

    @Override
    public GenericNamedObjectDao<Organization> getDao() {
        return organizationDao;
    }
}
