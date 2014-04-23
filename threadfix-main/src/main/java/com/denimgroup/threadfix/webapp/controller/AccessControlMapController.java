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

package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.Option;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.AccessControlMapService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.beans.AccessControlMapModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/configuration/users/{userId}")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class AccessControlMapController {
	
	public AccessControlMapController(){}
	
	protected final SanitizedLogger log = new SanitizedLogger(AccessControlMapController.class);
	
	private AccessControlMapService accessControlMapService;
	private UserService userService;
	private RoleService roleService;
	private OrganizationService organizationService;
	
	@Autowired
	public AccessControlMapController(UserService userService,
			OrganizationService organizationService,
			RoleService roleService,
			AccessControlMapService accessControlMapService) {
		this.accessControlMapService = accessControlMapService;
		this.userService = userService;
		this.roleService = roleService;
		this.organizationService = organizationService;
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}
	
	@RequestMapping(value="/permissions", method = RequestMethod.GET)
	public ModelAndView editForm(@PathVariable("userId") int userId) {
		User user = userService.loadUser(userId);
		
		if (user == null){
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		boolean isThisUser = currentUser != null && user.getName().equals(currentUser);
		
		ModelAndView mav = new ModelAndView("config/users/rolesConfiguration");
		mav.addObject(user);
		mav.addObject("teams",organizationService.loadAllActive());
		mav.addObject("maps",accessControlMapService.loadAllMapsForUser(userId));
		mav.addObject("accessControlMapModel", getMapModel(userId));
		mav.addObject("isThisUser", isThisUser);
		return mav;
	}

	@RequestMapping(value="/permissions/map", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Map<String, Object>> map(@PathVariable("userId") int userId) {
		Map<String, Object> returnMap = new HashMap<>();

        returnMap.put("maps", accessControlMapService.loadAllMapsForUser(userId));
        returnMap.put("teams", organizationService.loadAllActive());
        returnMap.put("roles", roleService.loadAll());

		return RestResponse.success(returnMap);
	}
	
	private AccessControlMapModel getMapModel(Integer userId) {
		AccessControlMapModel map = new AccessControlMapModel();
		map.setUserId(userId);
		return map;
	}
	
	@RequestMapping(value="/access/new", method = RequestMethod.POST)
	public @ResponseBody RestResponse<AccessControlTeamMap> createMapping(@PathVariable("userId") int userId,
			@ModelAttribute AccessControlMapModel accessControlModel) {

		User user = userService.loadUser(userId);
		if (user == null) {
			throw new ResourceNotFoundException();
		}
		
		accessControlModel.setUserId(userId);
		Option<AccessControlTeamMap> mapOption =
				accessControlMapService.parseAccessControlTeamMap(accessControlModel);

        if (mapOption.isValid()) {
            AccessControlTeamMap map = mapOption.getValue();
            map.setUser(user);

            String error = accessControlMapService.validateMap(map, null);
            if (error != null) {
                return RestResponse.failure(error);
            } else {
                accessControlMapService.store(map);
                return RestResponse.success(map);
            }
        } else {
            return RestResponse.failure("The map was not parsable from the given www-url-formencoded form.");
        }
	}
	
	@RequestMapping(value="/access/{mapId}/edit", method = RequestMethod.POST)
	public @ResponseBody RestResponse<AccessControlTeamMap> editMapping(@ModelAttribute AccessControlMapModel accessControlModel,
			@PathVariable("userId") int userId, 
			@PathVariable("mapId") int mapId) {
		
		User user = userService.loadUser(userId);
		if (user == null) {
			throw new ResourceNotFoundException();
		}
		
		accessControlModel.setUserId(userId);
		Option<AccessControlTeamMap> mapOption =
				accessControlMapService.parseAccessControlTeamMap(accessControlModel);

        if (mapOption.isValid()) {
            AccessControlTeamMap map = mapOption.getValue();

            map.setUser(user);

            String error = accessControlMapService.validateMap(map, mapId);
            if (error != null) {
                return RestResponse.failure(error);
            } else {

                accessControlMapService.deactivate(accessControlMapService.loadAccessControlTeamMap(mapId));
                accessControlMapService.store(map);
                return RestResponse.success(map);
            }
        } else {
    		return RestResponse.failure("Unable to parse HTML parameters.");
        }
	}
	
	@RequestMapping(value="/access/team/{mapId}/delete", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> deleteTeamMapping(@PathVariable("mapId") int mapId) {
		AccessControlTeamMap map = accessControlMapService.loadAccessControlTeamMap(mapId);
		accessControlMapService.deactivate(map);
		return RestResponse.success("Successfully deleted mapping.");
	}
	
	@RequestMapping(value="/access/app/{mapId}/delete", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> deleteAppMapping(@PathVariable("mapId") int mapId) {
		AccessControlApplicationMap map = accessControlMapService.loadAccessControlApplicationMap(mapId);
		accessControlMapService.deactivate(map);
		return RestResponse.success("Successfully deleted mapping.");
	}
}
