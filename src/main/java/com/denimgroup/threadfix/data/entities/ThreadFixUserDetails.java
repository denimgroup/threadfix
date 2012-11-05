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
package com.denimgroup.threadfix.data.entities;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class ThreadFixUserDetails extends User {

	private static final long serialVersionUID = -3748634330559506014L;

	private Boolean hasChangedInitialPassword = false;
	
	private Set<Integer> authenticatedTeamIds = null;

	private String salt;

	private Integer userId;
	
	private Map<Integer, Set<Permission>> teamMap, applicationMap;

	public ThreadFixUserDetails(String username, String password, boolean enabled,
			boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired,
				accountNonLocked, authorities);
	}

	public ThreadFixUserDetails(String username, String password, boolean enabled,
			boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<GrantedAuthority> authorities, String salt, Boolean hasChangedInitialPassword,
			Integer userId, Map<Integer, Set<Permission>> teamMap, 
			Map<Integer, Set<Permission>> applicationMap) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired,
				accountNonLocked, authorities);
		setTeamMap(teamMap);
		setApplicationMap(applicationMap);
		setSalt(salt);
		setHasChangedInitialPassword(hasChangedInitialPassword);
		setUserId(userId);
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	@Override
	public boolean equals(Object o) {
		return super.equals(o);
	}

	@Override
	public int hashCode() {
		return super.hashCode();
	}
	
	public Boolean hasChangedInitialPassword() {
		return hasChangedInitialPassword != null && hasChangedInitialPassword.booleanValue();
	}

	public void setHasChangedInitialPassword(Boolean hasChangedInitialPassword) {
		this.hasChangedInitialPassword = hasChangedInitialPassword;
	}
	
	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}

	public Set<Integer> getAuthenticatedTeamIds() {
		return authenticatedTeamIds;
	}

	public void setAuthenticatedTeamIds(Set<Integer> authenticatedTeamIds) {
		this.authenticatedTeamIds = authenticatedTeamIds;
	}

	public Map<Integer, Set<Permission>> getApplicationMap() {
		return applicationMap;
	}

	public void setApplicationMap(Map<Integer, Set<Permission>> applicationMap) {
		this.applicationMap = applicationMap;
	}

	public Map<Integer, Set<Permission>> getTeamMap() {
		return teamMap;
	}

	public void setTeamMap(Map<Integer, Set<Permission>> teamMap) {
		this.teamMap = teamMap;
	}
}
