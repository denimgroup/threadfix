package com.denimgroup.threadfix.data.entities;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name="UserGroupMap")
public class UserGroupMap extends AuditableEntity {

	private static final long serialVersionUID = 2846869499329276239L;

	private User user;
	private AccessGroup group;
	
	@ManyToOne
	@JoinColumn(name = "accessGroupId")
	public AccessGroup getAccessGroup() {
		return group;
	}
	
	public void setAccessGroup(AccessGroup group) {
		this.group = group;
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
