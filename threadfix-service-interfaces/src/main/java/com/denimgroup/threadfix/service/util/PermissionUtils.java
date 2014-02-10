package com.denimgroup.threadfix.service.util;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class PermissionUtils {

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
        return null;
    }

    public static Set<Integer> getAuthenticatedTeamIds() {
        return null;
    }
}
