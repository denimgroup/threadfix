////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.UserRoleMapDao;
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
	@Autowired
	private UserRoleMapDao userRoleMapDao;

	@Override
	public final UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userService.loadUser(username);
		if (user == null) {
			throw new UsernameNotFoundException("");
		}
		
		List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
		
		Integer id = user.getId();
		
		if (id != null) {
			List<Role> roles = userRoleMapDao.getRolesForUser(id);
		
			for (Role role : roles) {
				grantedAuthorities.add(new GrantedAuthorityImpl(role.getName()));
			}
		}
		
		ThreadFixUserDetails userDetails = new ThreadFixUserDetails(user.getName(),
				user.getPassword(), true, true, true, true, grantedAuthorities, user.getSalt(), 
				user.isHasChangedInitialPassword(), user.getId());

		return userDetails;
	}

}
