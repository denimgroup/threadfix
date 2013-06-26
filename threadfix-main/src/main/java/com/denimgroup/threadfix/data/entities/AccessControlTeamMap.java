package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name="AccessControlTeamMap")
public class AccessControlTeamMap extends AuditableEntity {

	private static final long serialVersionUID = -5845429359590418319L;
	private User user;
	private Organization organization;
	private Role role;
	private List<AccessControlApplicationMap> accessControlApplicationMaps;
	
	private Boolean allApps;
	
	@ManyToOne
    @JoinColumn(name = "userId", nullable = false)
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}
	
	@OneToMany(mappedBy = "accessControlTeamMap", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<AccessControlApplicationMap> getAccessControlApplicationMaps() {
		return accessControlApplicationMaps;
	}

	public void setAccessControlApplicationMaps(List<AccessControlApplicationMap> accessControlApplicationMaps) {
		this.accessControlApplicationMaps = accessControlApplicationMaps;
	}
	
	@ManyToOne
	@JoinColumn(name = "organizationId", nullable=false)
	@JsonIgnore
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}
	
	@ManyToOne
    @JoinColumn(name = "roleId", nullable = true)
	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	@Column
	public Boolean getAllApps() {
		return allApps;
	}

	public void setAllApps(Boolean allApps) {
		this.allApps = allApps;
	}
}
