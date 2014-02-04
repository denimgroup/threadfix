package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DefaultConfigServiceImpl implements DefaultConfigService {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigServiceImpl.class);
	
	@Autowired
	private DefaultConfigurationDao defaultConfigurationDao;

	@Override
	public DefaultConfiguration loadCurrentConfiguration() {
		List<DefaultConfiguration> list = defaultConfigurationDao.retrieveAll();
		if (list.size() == 0) {
            return DefaultConfiguration.getInitialConfig();
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
