package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;

public interface DefaultConfigurationDao {

	List<DefaultConfiguration> retrieveAll();
	
	void saveOrUpdate(DefaultConfiguration config);

	void delete(DefaultConfiguration config);
	
}
