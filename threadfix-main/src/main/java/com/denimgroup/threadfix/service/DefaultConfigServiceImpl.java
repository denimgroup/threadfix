package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;

@Service
public class DefaultConfigServiceImpl implements DefaultConfigService {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigServiceImpl.class);
	
	@Autowired
	private DefaultConfigurationDao defaultConfigurationDao;

	@Override
	public DefaultConfiguration loadCurrentConfiguration() {
		List<DefaultConfiguration> list = defaultConfigurationDao.retrieveAll();
		if (list.size() == 0) {
			DefaultConfiguration config = new DefaultConfiguration();
			config.setDefaultRoleId(1);
			config.setGlobalGroupEnabled(true);
			return config;
		}
		
		if (list.size() > 1) {
			DefaultConfiguration config = list.get(0);
			list.remove(0);
			for (DefaultConfiguration defaultConfig : list) {
				defaultConfigurationDao.delete(defaultConfig);
			}
			return config;
		}
		
		return list.get(0);
	}

	@Override
	public void saveConfiguration(DefaultConfiguration config) {
		defaultConfigurationDao.saveOrUpdate(config);
	}
}
