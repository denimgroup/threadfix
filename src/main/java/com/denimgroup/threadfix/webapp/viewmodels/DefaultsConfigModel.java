package com.denimgroup.threadfix.webapp.viewmodels;

import java.util.Properties;

import com.denimgroup.threadfix.service.SanitizedLogger;

public class DefaultsConfigModel {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultsConfigModel.class);

	private Boolean globalGroupEnabled = null;
	private Integer defaultRoleId = null;
	
	public Integer getDefaultRoleId() {
		return defaultRoleId;
	}
	public void setDefaultRoleId(Integer defaultRoleId) {
		this.defaultRoleId = defaultRoleId;
	}
	public Boolean getGlobalGroupEnabled() {
		return globalGroupEnabled != null && globalGroupEnabled;
	}
	public void setGlobalGroupEnabled(Boolean globalGroupEnabled) {
		this.globalGroupEnabled = globalGroupEnabled;
	}
	
	public Properties getProperties() {
		Properties toReturn = new Properties();
		
		if (defaultRoleId != null) {
			toReturn.setProperty("globalGroupEnabled", globalGroupEnabled.toString());
			toReturn.setProperty("defaultRoleId", defaultRoleId.toString());
		}
		
		return toReturn;
	}
	
	public DefaultsConfigModel(){}
	
	public DefaultsConfigModel(Properties properties) {
		if (properties != null) {
			String globalGroupEnabledString = properties.getProperty("globalGroupEnabled");
			String defaultRoleIdString = properties.getProperty("defaultRoleId");
			
			if (defaultRoleIdString != null) {
				Integer defaultRoleId = null;
				
				try {
					defaultRoleId = Integer.valueOf(defaultRoleIdString);
				} catch (NumberFormatException e) {
					log.warn("A non-double string was found in the threadfix default properties file.", e);
				}
				
				setDefaultRoleId(defaultRoleId);
			}
			
			setGlobalGroupEnabled(globalGroupEnabledString != null && globalGroupEnabledString.equals("true"));
		} 
	}
	
}
