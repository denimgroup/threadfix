////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

@Entity
@Table(name = "User")
public class User extends AuditableEntity {

	private static final long serialVersionUID = -5821877436246475858L;
	
	public static final int NAME_LENGTH = 40;
	public static final int PASSWORD_LENGTH = 256;

	private String name;
	private String password;
	private String salt;
	private boolean approved = true;
	private boolean locked = false;

	private Boolean hasGlobalGroupAccess = true;
	private Boolean hasChangedInitialPassword = false;
	private Date lastLoginDate = new Date();
	private Date lastPasswordChangedDate = new Date();
	private int failedPasswordAttempts = 0;
	private Date failedPasswordAttemptWindowStart = new Date();

	private String unencryptedPassword;
	private String passwordConfirm;
	private String currentPassword;
	
	private Role globalRole;

	@Column(length = NAME_LENGTH, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = PASSWORD_LENGTH, nullable = false)
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Column(length = PASSWORD_LENGTH, nullable = false)
	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	@Column(nullable = false)
	public boolean isApproved() {
		return approved;
	}

	public void setApproved(boolean approved) {
		this.approved = approved;
	}

	@Column(nullable = false)
	public boolean isLocked() {
		return locked;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
	public Date getLastPasswordChangedDate() {
		return lastPasswordChangedDate;
	}

	public void setLastPasswordChangedDate(Date lastPasswordChangedDate) {
		this.lastPasswordChangedDate = lastPasswordChangedDate;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
	public Date getLastLoginDate() {
		return lastLoginDate;
	}

	public void setLastLoginDate(Date lastLoginDate) {
		this.lastLoginDate = lastLoginDate;
	}

	@Column(nullable = false)
	public int getFailedPasswordAttempts() {
		return failedPasswordAttempts;
	}

	public void setFailedPasswordAttempts(int failedPasswordAttempts) {
		this.failedPasswordAttempts = failedPasswordAttempts;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
	public Date getFailedPasswordAttemptWindowStart() {
		return failedPasswordAttemptWindowStart;
	}

	public void setFailedPasswordAttemptWindowStart(Date failedPasswordAttemptWindowStart) {
		this.failedPasswordAttemptWindowStart = failedPasswordAttemptWindowStart;
	}

	@Transient
	public String getUnencryptedPassword() {
		return unencryptedPassword;
	}

	public void setUnencryptedPassword(String unencryptedPassword) {
		this.unencryptedPassword = unencryptedPassword;
	}

	@Transient
	public String getPasswordConfirm() {
		return passwordConfirm;
	}

	public void setPasswordConfirm(String passwordConfirm) {
		this.passwordConfirm = passwordConfirm;
	}

	@Transient
	public String getCurrentPassword() {
		return currentPassword;
	}

	public void setCurrentPassword(String currentPassword) {
		this.currentPassword = currentPassword;
	}

	//Hibernate naming conventions make this nasty although there may be a good way to do it
	@Column
	public Boolean isHasChangedInitialPassword() {
		return hasChangedInitialPassword;
	}

	public void setHasChangedInitialPassword(Boolean hasChangedInitialPassword) {
		this.hasChangedInitialPassword = hasChangedInitialPassword;
	}

	@Column
	public Boolean getHasGlobalGroupAccess() {
		return hasGlobalGroupAccess != null && hasGlobalGroupAccess;
	}

	public void setHasGlobalGroupAccess(Boolean hasGlobalGroupAccess) {
		this.hasGlobalGroupAccess = hasGlobalGroupAccess;
	}

	@ManyToOne
    @JoinColumn(name = "roleId", nullable = true)
	public Role getGlobalRole() {
		return globalRole;
	}

	public void setGlobalRole(Role globalRole) {
		this.globalRole = globalRole;
	}

}
