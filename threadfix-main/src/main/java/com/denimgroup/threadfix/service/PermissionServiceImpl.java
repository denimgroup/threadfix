package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.data.entities.Waf;

@Service
public class PermissionServiceImpl implements PermissionService {
	
	@Override
	public boolean isAuthorized(Permission permission, Integer orgId, Integer appId) {
		if (PermissionUtils.hasGlobalPermission(permission)) {
			return true;
		}
		
		if (orgId == null && appId == null) {
			return false;
		}
		
		ThreadFixUserDetails customAuth = null;
		
		Object auth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (auth != null && auth instanceof ThreadFixUserDetails) {
			customAuth = (ThreadFixUserDetails) auth;
			
			if (customAuth.getTeamMap() != null && orgId != null &&
					customAuth.getTeamMap().containsKey(orgId) &&
					customAuth.getTeamMap().get(orgId) != null &&
					customAuth.getTeamMap().get(orgId).contains(permission)) {
				return true;
			}
			
			if (customAuth.getApplicationMap() != null && appId != null &&
					customAuth.getApplicationMap().containsKey(appId) &&
					customAuth.getApplicationMap().get(appId) != null &&
					customAuth.getApplicationMap().get(appId).contains(permission)) {
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public void addPermissions(ModelAndView modelAndView, Integer orgId,
			Integer appId, Permission... permissions) {
		for (Permission permission : permissions) {
			modelAndView.addObject(permission.getCamelCase(), isAuthorized(permission, orgId, appId));
		}
	}
	
	@Override
	public void addPermissions(Model model, Integer orgId, Integer appId,
			Permission... permissions) {
		for (Permission permission : permissions) {
			model.addAttribute(permission.getCamelCase(), isAuthorized(permission, orgId, appId));
		}
	}

	@Override
	public boolean canSeeRules(Waf waf) {
		if (waf == null || waf.getApplications() == null ||
				waf.getApplications().size() == 0) {
			return false;
		}
		
		if (PermissionUtils.hasGlobalPermission(Permission.READ_ACCESS)) {
			return true;
		}
		
		boolean denied = false;
		for (Application app : waf.getApplications()) {
			if (app == null || app.getId() == null ||
					app.getOrganization() == null ||
					app.getOrganization().getId() == null)
			{
				return false;
			}
			else if (!isAuthorized(Permission.CAN_GENERATE_WAF_RULES,
							app.getOrganization().getId(), app.getId())) {
				denied = true;
			}
		}
		
		if (!denied) {
			return true;
		}
		
		return false;
	}

	@Override
	public Set<Integer> getAuthenticatedAppIds() {
		Object auth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (auth != null && auth instanceof ThreadFixUserDetails) {
			if (((ThreadFixUserDetails) auth).getAuthorities().contains(
					new GrantedAuthorityImpl(Permission.READ_ACCESS.getText()))) {
				return null;
			}
			
			if (((ThreadFixUserDetails) auth).getApplicationMap() != null) {
				return ((ThreadFixUserDetails) auth).getApplicationMap().keySet();
			}
		}
		
		return null;
	}
	
	@Override
	public Set<Integer> getAuthenticatedTeamIds() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (principal instanceof ThreadFixUserDetails) {
			ThreadFixUserDetails customDetails = (ThreadFixUserDetails) principal;
			
			if (customDetails.getAuthorities().contains(
					new GrantedAuthorityImpl(Permission.READ_ACCESS.getText()))) {
				return null;
			}

			if (customDetails.getTeamMap() != null) {
				return customDetails.getTeamMap().keySet();
			}
		}
		
		return null;
	}

	@Override
	public List<Application> filterApps(Organization organization) {

		List<Application> newApps = new ArrayList<Application>();

		if (organization == null || organization.getActiveApplications() == null) {
			return newApps;
		}
		if (PermissionUtils.hasGlobalPermission(Permission.READ_ACCESS)) {
			return organization.getActiveApplications();
		}
		
		Set<Integer> orgIds = getAuthenticatedTeamIds();
		if (orgIds != null && orgIds.contains(organization.getId())) {
			return organization.getActiveApplications();
		}
		
		Set<Integer> appIds = getAuthenticatedAppIds();
		if (appIds == null) {
			// it should be impossible to get here.
			// if it somehow does happen then the user definitely shouldn't see any apps.
			return newApps;
		}
		
		for (Application app : organization.getActiveApplications()) {
			if (appIds.contains(app.getId())) {
				newApps.add(app);
			}
		}
		
		return newApps;
	}
	
	@Override
	public void filterApps(List<RemoteProviderType> providers) {
		boolean global = PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_REMOTE_PROVIDERS);

		for (RemoteProviderType type : providers) {
			if (global) {
				type.setFilteredApplications(type.getRemoteProviderApplications());
			} else {
				type.setFilteredApplications(new ArrayList<RemoteProviderApplication>());
				for (RemoteProviderApplication app : type.getRemoteProviderApplications()) {
					if (app.getApplication() != null && app.getApplication().getId() != null &&
							app.getApplication().getOrganization() != null &&
							app.getApplication().getOrganization().getId() != null &&
							isAuthorized(Permission.CAN_UPLOAD_SCANS,
									app.getApplication().getOrganization().getId(),
									app.getApplication().getId())) {
						type.getFilteredApplications().add(app);
					}
				}
			}
		}
	}
}
