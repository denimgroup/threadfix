////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service.util;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.ThreadFixUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listFrom;

@Component
public class PermissionUtils extends SpringBeanAutowiringSupport {

    @Autowired(required = false)
    private PermissionService permissionService;

    private boolean isCommunity() {
        return permissionService == null;
    }

    // This is only ok because it's stateless
    private static PermissionUtils INSTANCE = null;

    private static PermissionUtils getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new PermissionUtils();
        }

        return INSTANCE;
    }

    public static final List<String> ENTERPRISE_PROVIDERS = list(ScannerType.CHECKMARX.getDisplayName());

	public static boolean hasGlobalPermission(Permission permission) {
		if (permission == null || permission.getText() == null) {
			return false;
		}
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		return authentication != null && authentication
				.getAuthorities().contains(new SimpleGrantedAuthority(permission.getText()));
	}

	public static boolean hasGlobalPermission(Collection<? extends GrantedAuthority> authorities, Permission permission) {
		if (permission == null || permission.getText() == null || authorities == null) {
			return false;
		}

		return authorities.contains(new SimpleGrantedAuthority(permission.getText()));
	}

	public static boolean hasGlobalReadAccess() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return authentication != null && authentication.getAuthorities().contains(
						new SimpleGrantedAuthority(Permission.READ_ACCESS.getText()));
	}

    public static boolean isAuthorized(Permission permission) {
        return isAuthorized(permission, null, null);
    }

    public static boolean isAuthorized(Permission permission, Integer orgId) {
        return isAuthorized(permission, orgId, null);
    }

    public static boolean isAuthorized(Permission permission, Integer orgId, Integer appId) {
        return getInstance().isCommunity() ||
                getInstance().permissionService.isAuthorized(permission, orgId, appId);
    }

    public static boolean isAuthorized(ThreadFixUserDetails details, Permission permission, Integer orgId, Integer appId) {
        return getInstance().isCommunity() ||
                getInstance().permissionService.isAuthorized(details, permission, orgId, appId);
    }

    public static void addPermissions(ModelAndView modelAndView, Integer orgId,
                                      Integer appId, Permission... permissions) {
        if (getInstance().isCommunity()) {
            for (Permission permission : permissions) {
                modelAndView.addObject(permission.getCamelCase(), true);
            }
        } else {
            getInstance().permissionService.addPermissions(modelAndView, orgId, appId, permissions);
        }
    }

    public static void addPermissions(Model model, Integer orgId,
                                      Integer appId, Permission... permissions) {
        if (getInstance().isCommunity()) {
            for (Permission permission : permissions) {
                model.addAttribute(permission.getCamelCase(), true);
            }
        } else {
            getInstance().permissionService.addPermissions(model, orgId, appId, permissions);
        }
    }

    public static List<Application> filterApps(Organization organization) {

        if (getInstance().isCommunity()) {
            List<Application> newApps = list();

            if (organization == null || organization.getActiveApplications() == null) {
                return newApps;
            }
            return organization.getActiveApplications();
        } else {
            return getInstance().permissionService.filterApps(organization);
        }
    }

    public static void filterApps(List<RemoteProviderType> providers) {
        if (getInstance().isCommunity()) {
            // TODO remove CheckMarx provider
            for (RemoteProviderType type : providers) {
                type.setFilteredApplications(type.getRemoteProviderApplications());
            }
        } else {
            getInstance().permissionService.filterApps(providers);
        }
    }

    public static void filterAvailableProviders(List<RemoteProviderType> providers) {
        List<RemoteProviderType> providersToRemove = list();
        if (getInstance().isCommunity()) {
            for (RemoteProviderType remoteProviderType : providers) {
                if (ENTERPRISE_PROVIDERS.contains(remoteProviderType.getChannelType().getName())) {
                    providersToRemove.add(remoteProviderType);
                }
            }
        }
        providers.removeAll(providersToRemove);
    }

    public static boolean canSeeRules(Waf waf) {
        return getInstance().isCommunity() || getInstance().permissionService.canSeeRules(waf);
    }

    public static Set<Integer> getAuthenticatedAppIds() {
        if (getInstance().isCommunity()) {
            return null;
        } else {
            return getInstance().permissionService.getAuthenticatedAppIds();
        }
    }

    public static Set<Integer> getAuthenticatedAppIds(ThreadFixUserDetails details) {
        if (getInstance().isCommunity()) {
            return null;
        } else {
            return getInstance().permissionService.getAuthenticatedAppIds(details);
        }
    }

    public static Set<Integer> getAuthenticatedTeamIds() {
        if (getInstance().isCommunity()) {
            return null;
        } else {
            return getInstance().permissionService.getAuthenticatedTeamIds();
        }
    }

    public static Set<Integer> getAuthenticatedTeamIds(ThreadFixUserDetails details) {
        if (getInstance().isCommunity()) {
            return null;
        } else {
            return getInstance().permissionService.getAuthenticatedTeamIds(details);
        }
    }

    public static List<Organization> filterTeamList(List<Organization> organizations) {

        Set<Integer> teamIds = getAuthenticatedTeamIds();

        // If community or global read access, return all teams.
        if (teamIds == null) { // TODO use something other than null to indicate all permissions
            return organizations;
        }

        List<Organization> returnList = list();
        for (Organization organization : organizations) {
            if (teamIds.contains(organization.getId())) {
                returnList.add(organization);
            } else {
                List<Application> applications = filterApps(organization);

                if (applications != null && !applications.isEmpty()) {
                    organization.setActiveApplications(applications);
                    organization.setApplications(applications);
                    organization.updateVulnerabilityReport();
                    returnList.add(organization);
                }
            }
        }

        return returnList;
    }

    public static List<Application> filterAppsList(List<Organization> organizations) {

        Set<Integer> teamIds = getAuthenticatedTeamIds();
        List<Application> returnApps = list();

        // If community or global read access, return all teams.
        if (teamIds == null) { // TODO use something other than null to indicate all permissions
            for (Organization org: organizations)
                returnApps.addAll(org.getActiveApplications());
            return returnApps;
        }

        for (Organization organization : organizations) {
            if (teamIds.contains(organization.getId())) {
                returnApps.addAll(organization.getActiveApplications());
            } else {
                List<Application> applications = filterApps(organization);

                if (applications != null && !applications.isEmpty()) {
                    returnApps.addAll(applications);
                }
            }
        }

        return returnApps;
    }

    public static List<Integer> getIdsWithPermission(Permission permission, List<Organization> organizations) {
        List<Integer> returnList = list();

        for (Organization organization : organizations) {
            Integer id = organization.getId();
            if (id != null && isAuthorized(permission, id, null)) {
                returnList.add(id);
            }
        }

        return returnList;
    }

    public static List<Integer> getAppIdsWithPermission(Permission permission, List<Organization> organizations) {
        List<Integer> returnList = list();

        for (Organization organization : organizations) {
            Integer teamId = organization.getId();
            for (Application application : organization.getApplications()) {
                Integer applicationId = application.getId();

                if (teamId != null && applicationId != null && isAuthorized(permission, teamId, applicationId)) {
                    returnList.add(applicationId);
                }

            }
        }

        return returnList;
    }
}
