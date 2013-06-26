package com.denimgroup.threadfix.data.entities;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name="AccessControlApplicationMap")
public class AccessControlApplicationMap extends AuditableEntity {

	private static final long serialVersionUID = -7676228258207971711L;
	private AccessControlTeamMap accessControlTeamMap;
	private Application application;
	private Role role;
	
	@ManyToOne
    @JoinColumn(name = "accessControlTeamMapId", nullable = false)
	public AccessControlTeamMap getAccessControlTeamMap() {
		return accessControlTeamMap;
	}

	public void setAccessControlTeamMap(AccessControlTeamMap accessControlTeamMap) {
		this.accessControlTeamMap = accessControlTeamMap;
	}
	
	@ManyToOne
	@JoinColumn(name = "applicationId", nullable = false)
	@JsonIgnore
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}
	
	@ManyToOne
    @JoinColumn(name = "roleId", nullable = true)
	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}
	
}
