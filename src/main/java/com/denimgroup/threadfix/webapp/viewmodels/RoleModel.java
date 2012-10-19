package com.denimgroup.threadfix.webapp.viewmodels;

import com.denimgroup.threadfix.data.entities.Role;

public class RoleModel {
	
	private Role role;
	
	private boolean canDelete;

	public RoleModel(Role role, boolean canDelete) {
		setRole(role);
		setCanDelete(canDelete);
	}
	
	public boolean isCanDelete() {
		return canDelete;
	}

	public void setCanDelete(boolean canDelete) {
		this.canDelete = canDelete;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

}
