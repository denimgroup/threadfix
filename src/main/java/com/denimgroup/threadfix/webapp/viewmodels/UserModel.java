package com.denimgroup.threadfix.webapp.viewmodels;

import com.denimgroup.threadfix.data.entities.User;

public class UserModel {

	private User user;
	
	private boolean isDeletable, isThisUser;
	
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public boolean isDeletable() {
		return isDeletable;
	}

	public void setDeletable(boolean isDeletable) {
		this.isDeletable = isDeletable;
	}

	public boolean isThisUser() {
		return isThisUser;
	}

	public void setThisUser(boolean isThisUser) {
		this.isThisUser = isThisUser;
	}
	
}
