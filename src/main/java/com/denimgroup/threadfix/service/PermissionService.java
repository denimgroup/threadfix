package com.denimgroup.threadfix.service;

import java.util.List;
import java.util.Set;

import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;

public interface PermissionService {

	/**
	 * 
	 * @param orgId
	 * @return
	 */
	boolean isAuthorized(Permission permission, Integer orgId, Integer appId);
	
	/**
	 * 
	 * @param model
	 * @param orgId
	 * @param appId
	 * @param permissions
	 */
	void addPermissions(Model model, Integer orgId, Integer appId, Permission... permissions);
	
	/**
	 * 
	 * @param model
	 * @param orgId
	 * @param appId
	 * @param permissions
	 */
	void addPermissions(ModelAndView modelAndView, Integer orgId, Integer appId, Permission... permissions);
	
	/**
	 * 
	 * @param waf
	 * @return
	 */
	boolean canSeeRules(Waf waf);
	
	/**
	 * 
	 * @return
	 */
	Set<Integer> getAuthenticatedAppIds();
	
	/**
	 * This method returns null if the user has access to all teams.
	 * TODO revisit this section
	 * @return
	 */
	Set<Integer> getAuthenticatedTeamIds();

	/**
	 * 
	 * @param organization
	 * @return
	 */
	List<Application> filterApps(Organization organization);
	
}
