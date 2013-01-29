////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.data.entities.User;

/**
 * @author cleclair
 * @author mcollins
 * 
 */
@Service
public class CustomUserDetailService implements UserDetailsService {

	@Autowired
	private UserService userService;
	
	public UserDetails loadUser(User user) {
		if (user == null) {
			return null;
		}
		
		List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
		
		Map<Integer, Set<Permission>> orgMap = null;
		Map<Integer, Set<Permission>> appMap = null;
		
		Integer id = user.getId();
		
		// Transfer the set of permissions that the user has to GrantedAuthority objects
		if (id != null) {
			Set<Permission> permissions = userService.getGlobalPermissions(id);
		
			for (Permission permission : permissions) {
				grantedAuthorities.add(new GrantedAuthorityImpl(permission.getText()));
			}
			
			// For now
			grantedAuthorities.add(new GrantedAuthorityImpl(Role.USER));
			
			if (user.getHasGlobalGroupAccess()) {
				grantedAuthorities.add(new GrantedAuthorityImpl(Permission.READ_ACCESS.getText()));
			}
			
			orgMap = userService.getOrganizationPermissions(id);
			appMap = userService.getApplicationPermissions(id);
			
			if (hasReportsOnAnyObject(orgMap) || hasReportsOnAnyObject(appMap)) {
				grantedAuthorities.add(new GrantedAuthorityImpl(Permission.CAN_GENERATE_REPORTS.getText()));
			}
		}
		
		ThreadFixUserDetails userDetails = new ThreadFixUserDetails(user.getName(),
				user.getPassword(), true, true, true, true, grantedAuthorities, user.getSalt(), 
				user.isHasChangedInitialPassword(), user.getId(), orgMap, appMap);
		
		userService.storeUser(user);

		return userDetails;
	}

	@Override
	public final UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userService.loadUser(username);
		if (user == null) {
			throw new UsernameNotFoundException("");
		}
		
		return loadUser(user);
	}
	
	private boolean hasReportsOnAnyObject(Map<Integer, Set<Permission>> map) {
		if (map == null || map.isEmpty()) {
			return false;
		}
		
		for (Set<Permission> perms : map.values()) {
			if (perms.contains(Permission.CAN_GENERATE_REPORTS)) {
				return true;
			}
		}
		return false;
	}
	
}
