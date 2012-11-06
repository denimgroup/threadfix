package com.denimgroup.threadfix.service;

import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;

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
	
}
