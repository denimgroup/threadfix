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

package com.denimgroup.threadfix.service.util;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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
            assert INSTANCE.permissionService != null :
                    "Spring configuration is wrong, try again.";
        }

        return INSTANCE;
    }

	public static boolean hasGlobalPermission(Permission permission) {
		if (permission == null || permission.getText() == null) {
			return false;
		}
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return authentication != null && authentication
				.getAuthorities().contains(new SimpleGrantedAuthority(permission.getText()));
	}

	public static boolean hasGlobalReadAccess() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return authentication != null && authentication.getAuthorities().contains(
						new SimpleGrantedAuthority(Permission.READ_ACCESS.getText()));
	}

    public static boolean isAuthorized(Permission canUploadScans, Integer orgId, Integer appId) {
        return getInstance().isCommunity() ||
                getInstance().permissionService.isAuthorized(canUploadScans, orgId, appId);
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
            List<Application> newApps = new ArrayList<>();

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
            for (RemoteProviderType type : providers) {
                type.setFilteredApplications(type.getRemoteProviderApplications());
            }
        } else {
            getInstance().permissionService.filterApps(providers);
        }
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

    public static Set<Integer> getAuthenticatedTeamIds() {
        if (getInstance().isCommunity()) {
            return null;
        } else {
            return getInstance().permissionService.getAuthenticatedTeamIds();
        }
    }
}
