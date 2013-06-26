package com.denimgroup.threadfix.webapp.viewmodels;

import com.denimgroup.threadfix.data.entities.User;

public class UserModel {

	private User user;
	
	private boolean deletable, thisUser;
	
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public boolean isDeletable() {
		return deletable;
	}

	public void setDeletable(boolean isDeletable) {
		this.deletable = isDeletable;
	}

	public boolean isThisUser() {
		return thisUser;
	}

	public void setThisUser(boolean isThisUser) {
		this.thisUser = isThisUser;
	}
	
}
