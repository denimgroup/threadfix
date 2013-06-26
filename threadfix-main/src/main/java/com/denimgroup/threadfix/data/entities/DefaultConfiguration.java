package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Table;
import javax.persistence.Entity;

@Entity
@Table(name="DefaultConfiguration")
public class DefaultConfiguration extends BaseEntity {
	
	private static final long serialVersionUID = 2584623185996706729L;
	
	private Boolean globalGroupEnabled = null;
	private Integer defaultRoleId = null;
	
	@Column
	public Integer getDefaultRoleId() {
		return defaultRoleId;
	}
	public void setDefaultRoleId(Integer defaultRoleId) {
		this.defaultRoleId = defaultRoleId;
	}
	
	@Column
	public Boolean getGlobalGroupEnabled() {
		return globalGroupEnabled != null && globalGroupEnabled;
	}
	public void setGlobalGroupEnabled(Boolean globalGroupEnabled) {
		this.globalGroupEnabled = globalGroupEnabled;
	}
}
