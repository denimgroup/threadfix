////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.login.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Nullable;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * @author cleclair
 * @author mcollins
 * 
 */
@Service
public class CustomUserDetailServiceImpl implements UserDetailsService, CustomUserDetailService {

    protected final SanitizedLogger log = new SanitizedLogger(CustomUserDetailServiceImpl.class);

    @Autowired
    private UserService userService;

    @Autowired(required = false)
    @Nullable
    private PermissionService permissionService;

    @Override
    public UserDetails loadUser(User user) {
        if (user == null) {
            return null;
        }

        List<GrantedAuthority> grantedAuthorities = list();

        Map<Integer, Set<Permission>> orgMap = null;
        Map<Integer, Set<Permission>> appMap = null;

        Integer id = user.getId();

        // For now
        grantedAuthorities.add(new SimpleGrantedAuthority(Role.USER));

        // Transfer the set of permissions that the user has to GrantedAuthority objects
        if (id != null) {

            if (permissionService != null) { // then we've autowired the dependency in successfully

                Set<Permission> permissions = userService.getGlobalPermissions(id);

                for (Permission permission : permissions) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(permission.getText()));
                }

                if (user.getHasGlobalGroupAccess()) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(Permission.READ_ACCESS.getText()));
                }

                orgMap = userService.getOrganizationPermissions(id);
                appMap = userService.getApplicationPermissions(id);

                if (hasReportsOnAnyObject(orgMap) || hasReportsOnAnyObject(appMap)) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(Permission.CAN_GENERATE_REPORTS.getText()));
                }
            } else {
                for (Permission permission : Permission.values()) {
                    if (permission != Permission.CAN_MANAGE_ROLES && permission != Permission.ENTERPRISE) {
                        grantedAuthorities.add(new SimpleGrantedAuthority(permission.getText()));
                    }
                }
            }
        }

        ThreadFixUserDetails userDetails = new ThreadFixUserDetails(user.getBestName(),
                user.getPassword(), true, true, true, true, grantedAuthorities, user.getSalt(),
                user.isHasChangedInitialPassword(), user.getIsLdapUser(),
                user.getId(), orgMap, appMap);

        userService.storeUser(user);

        return userDetails;
    }

    @Override
    public final UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.loadUser(username);
        if (user == null) {
            if (userService.countUsers() == 0) {
                log.debug("There appears to be no users in your DBS. Your database might not have been created correctly.");
                throw new AuthenticationServiceException("Check logs");
            }
            throw new UsernameNotFoundException("");
        }

        log.info("User " + user.getName() + " logged in successfully at " + new Date());
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
