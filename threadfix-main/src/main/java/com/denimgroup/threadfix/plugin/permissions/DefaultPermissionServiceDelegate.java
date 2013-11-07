package com.denimgroup.threadfix.plugin.permissions;

import java.util.List;
import java.util.Set;

import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;

public class DefaultPermissionServiceDelegate implements PermissionService {
	
	protected SanitizedLogger log = null;
	
	@Override
	public boolean isAuthorized(Permission permission, Integer orgId,
			Integer appId) {
		return true;
	}

	@Override
	public void addPermissions(Model model, Integer orgId, Integer appId,
			Permission... permissions) {
		for (Permission permission : permissions) {
			model.addAttribute(permission.getCamelCase(), true);
		}
	}

	@Override
	public void addPermissions(ModelAndView modelAndView, Integer orgId,
			Integer appId, Permission... permissions) {
		for (Permission permission : permissions) {
			modelAndView.addObject(permission.getCamelCase(), true);
		}
	}

	@Override
	public boolean canSeeRules(Waf waf) {
		return true;
	}

	@Override
	public Set<Integer> getAuthenticatedAppIds() {
		return null; // means all apps
	}

	@Override
	public Set<Integer> getAuthenticatedTeamIds() {
		return null; // means all apps
	}

	@Override
	public List<Application> filterApps(Organization organization) {
		return organization.getActiveApplications();
	}

	@Override
	public void filterApps(List<RemoteProviderType> providers) {
        for (RemoteProviderType type : providers) {
            type.setFilteredApplications(type.getRemoteProviderApplications());
        }
	}
	
	@Override
	public boolean isEnterprise() {
		return false;
	}
	
	@Override
	public void setLogger(SanitizedLogger log){
		this.log  = log;
	}

}
