package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;

public interface DefaultConfigService {

	/**
	 * Load the current system settings
	 * @return
	 */
	DefaultConfiguration loadCurrentConfiguration();
	
	/**
	 * Save new system settings
	 * @param model
	 */
	void saveConfiguration(DefaultConfiguration config);
}
