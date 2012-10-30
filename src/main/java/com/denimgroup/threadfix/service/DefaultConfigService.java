package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.webapp.viewmodels.DefaultsConfigModel;

public interface DefaultConfigService {

	/**
	 * Load the current system settings
	 * @return
	 */
	DefaultsConfigModel loadCurrentConfiguration();
	
	/**
	 * Save new system settings
	 * @param model
	 */
	void saveConfiguration(DefaultsConfigModel model);
}
