package com.denimgroup.threadfix.data.entities;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name="UserRoleMap")
public class UserRoleMap extends AuditableEntity {

	private static final long serialVersionUID = -4800446844037087810L;
	
	private User user;
	private Role role;
	
	@ManyToOne
	@JoinColumn(name = "roleId")
	public Role getRole() {
		return role;
	}
	
	public void setRole(Role role) {
		this.role = role;
	}

	@ManyToOne
	@JoinColumn(name = "userId")
	public User getUser() {
		return user;
	}
	
	public void setUser(User user) {
		this.user = user;
	}
}
