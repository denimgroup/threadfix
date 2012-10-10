package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.AccessGroup;

public interface AccessGroupDao {

	/**
	 * @return
	 */
	List<AccessGroup> retrieveAll();

	/**
	 * @param id
	 * @return
	 */
	AccessGroup retrieveById(int id);
	
	/**
	 * 
	 * @param key
	 * @return
	 */
	AccessGroup retrieveByName(String name);
	
	/**
	 * @param survey
	 */
	void saveOrUpdate(AccessGroup group);

}
