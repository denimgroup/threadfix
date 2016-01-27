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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name="AccessControlApplicationMap")
public class AccessControlApplicationMap extends AuditableEntity {

	private static final long serialVersionUID = -7676228258207971711L;
	private AccessControlTeamMap accessControlTeamMap;
	private Application application;
	private Role role;
	
	@ManyToOne
    @JsonIgnore
    @JoinColumn(name = "accessControlTeamMapId", nullable = false)
	public AccessControlTeamMap getAccessControlTeamMap() {
		return accessControlTeamMap;
	}

	public void setAccessControlTeamMap(AccessControlTeamMap accessControlTeamMap) {
		this.accessControlTeamMap = accessControlTeamMap;
	}
	
	@ManyToOne
    @JsonView(AllViews.TableRow.class)
    @JoinColumn(name = "applicationId", nullable = false)
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}
	
	@ManyToOne
    @JsonView(AllViews.TableRow.class)
    @JoinColumn(name = "roleId", nullable = true)
	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}
	
}
