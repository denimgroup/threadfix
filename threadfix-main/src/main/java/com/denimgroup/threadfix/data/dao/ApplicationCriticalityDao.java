package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.ApplicationCriticality;

/**
 * 
 * @author mcollins
 *
 */
public interface ApplicationCriticalityDao {

	/**
	 * @return
	 */
	List<ApplicationCriticality> retrieveAll();


	/**
	 * @param id
	 * @return
	 */
	ApplicationCriticality retrieveById(int id);

	/**
	 * @param name
	 * @return
	 */
	ApplicationCriticality retrieveByName(String name);
	
}
