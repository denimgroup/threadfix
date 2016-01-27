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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.*;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;
import java.util.Set;

public interface PermissionService {
	
	boolean isEnterprise();

	/**
	 * 
	 * @param orgId
	 * @return
	 */
	boolean isAuthorized(Permission permission, Integer orgId, Integer appId);

	/**
	 *
	 * @param orgId
	 * @return
	 */
	boolean isAuthorized(ThreadFixUserDetails userDetails, Permission permission, Integer orgId, Integer appId);
	
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

	Set<Integer> getAuthenticatedAppIds(ThreadFixUserDetails details);

	/**
	 * This method returns null if the user has access to all teams.
	 * TODO revisit this section
	 * @return
	 */
	Set<Integer> getAuthenticatedTeamIds();

	Set<Integer> getAuthenticatedTeamIds(ThreadFixUserDetails details);

	/**
	 *
	 * @param organization
	 * @return
	 */
	List<Application> filterApps(Organization organization);

	/**
	 *
	 * @param providers
	 */
	void filterApps(List<RemoteProviderType> providers);
}
