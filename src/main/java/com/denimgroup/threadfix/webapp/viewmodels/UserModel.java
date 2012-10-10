package com.denimgroup.threadfix.webapp.viewmodels;

import com.denimgroup.threadfix.data.entities.User;

public class UserModel {

	private User user;
	
	private boolean isLastAdmin, isThisUser;
	
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public boolean isLastAdmin() {
		return isLastAdmin;
	}

	public void setLastAdmin(boolean isLastAdmin) {
		this.isLastAdmin = isLastAdmin;
	}

	public boolean isThisUser() {
		return isThisUser;
	}

	public void setThisUser(boolean isThisUser) {
		this.isThisUser = isThisUser;
	}
	
}
