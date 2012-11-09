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
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.data.entities.Waf;

@Service
public class PermissionServiceImpl implements PermissionService {

	public boolean hasGlobalPermission(Permission permission) {
		return SecurityContextHolder.getContext().getAuthentication()
				.getAuthorities().contains(new GrantedAuthorityImpl(permission.getText()));
	}
	
	@Override
	public boolean isAuthorized(Permission permission, Integer orgId, Integer appId) {
		if (hasGlobalPermission(permission))
			return true;
		
		if (orgId == null && appId == null) {
			return false;
		}
		
		ThreadFixUserDetails customAuth = null;
		
		Object auth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (auth != null && auth instanceof ThreadFixUserDetails) {
			customAuth = (ThreadFixUserDetails) auth;
			
			if (customAuth != null && customAuth.getTeamMap() != null &&
					orgId != null && customAuth.getTeamMap().containsKey(orgId) &&
					customAuth.getTeamMap().get(orgId) != null &&
					customAuth.getTeamMap().get(orgId).contains(permission)) {
				return true;
			}
			
			if (customAuth != null && customAuth.getApplicationMap() != null &&
					appId != null && customAuth.getApplicationMap().containsKey(appId) &&
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
			return true;
		}
		
		if (hasGlobalPermission(Permission.READ_ACCESS)) {
			return true;
		}
		
		for (Application app : waf.getApplications()) {
			if (app == null || app.getId() == null || 
					app.getOrganization() == null ||
					app.getOrganization().getId() == null ||
					!isAuthorized(Permission.CAN_GENERATE_WAF_RULES, 
							app.getOrganization().getId(), app.getId())) {
				return false;
			}
		}
		
		return true;
	}

	@Override
	public Set<Integer> getAuthenticatedAppIds() {
		Object auth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (auth != null && auth instanceof ThreadFixUserDetails) {
			if (((ThreadFixUserDetails) auth).getAuthorities().contains(
					new GrantedAuthorityImpl(Permission.READ_ACCESS.getText()))) {
				return null;
			}
			return ((ThreadFixUserDetails) auth).getApplicationMap().keySet();
		}
		
		return null;
	}
	
	@Override
	public Set<Integer> getAuthenticatedTeamIds() {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (principal instanceof ThreadFixUserDetails) {
			ThreadFixUserDetails customDetails = ((ThreadFixUserDetails) principal);
			
			if (customDetails.getAuthorities().contains(
					new GrantedAuthorityImpl(Permission.READ_ACCESS.getText()))) {
				return null;
			}

			return customDetails.getTeamMap().keySet();
		}
		
		return null;
	}

	@Override
	public List<Application> filterApps(Organization organization) {
		if (hasGlobalPermission(Permission.READ_ACCESS)) {
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
			return new ArrayList<Application>();
		}
		
		List<Application> newApps = new ArrayList<Application>();
		for (Application app : organization.getActiveApplications()) {
			if (appIds.contains(app.getId())) {
				newApps.add(app);
			}
		}
		
		return newApps;
	}
}
