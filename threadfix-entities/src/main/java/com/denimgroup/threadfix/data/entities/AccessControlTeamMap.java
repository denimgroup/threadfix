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

package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="AccessControlTeamMap")
public class AccessControlTeamMap extends AuditableEntity {

	private static final long serialVersionUID = -5845429359590418319L;
	private User user;
	private Group group;
	private Organization organization;
	private Role role;
	private List<AccessControlApplicationMap> accessControlApplicationMaps;
	
	private Boolean allApps;
	
	@ManyToOne
    @JoinColumn(name = "userId", nullable = true)
    @JsonView(Object.class)
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@ManyToOne
	@JoinColumn(name = "groupId", nullable = true)
	public Group getGroup() {
		return group;
	}

	public void setGroup(Group group) {
		this.group = group;
	}

	@OneToMany(mappedBy = "accessControlTeamMap", cascade = CascadeType.ALL)
    @JsonView(AllViews.TableRow.class)
	public List<AccessControlApplicationMap> getAccessControlApplicationMaps() {
		return accessControlApplicationMaps;
	}

	public void setAccessControlApplicationMaps(List<AccessControlApplicationMap> accessControlApplicationMaps) {
		this.accessControlApplicationMaps = accessControlApplicationMaps;
	}
	
	@ManyToOne
    @JsonView(Object.class)
	@JoinColumn(name = "organizationId", nullable=false)
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}
	
	@ManyToOne
    @JsonView(Object.class)
    @JoinColumn(name = "roleId", nullable = true)
	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	@Column
    @JsonView(Object.class)
	public Boolean getAllApps() {
		return allApps;
	}

	public void setAllApps(Boolean allApps) {
		this.allApps = allApps;
	}


	@Override
	public String toString() {
		return "AccessControlTeamMap{" +
				"organization=" + organization +
				", role=" + role +
				'}';
	}
}
