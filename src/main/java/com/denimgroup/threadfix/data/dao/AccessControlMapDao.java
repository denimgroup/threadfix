package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;

public interface AccessControlMapDao {

	/**
	 * @param id
	 * @return
	 */
	AccessControlTeamMap retrieveTeamMapById(int id);
	
	/**
	 * @param id
	 * @return
	 */
	AccessControlApplicationMap retrieveAppMapById(int id);
	
	/**
	 * @param id
	 * @return
	 */
	List<AccessControlTeamMap> retrieveAllMapsForUser(Integer id);

	/**
	 * @param survey
	 */
	void saveOrUpdate(AccessControlTeamMap map);
	
	/**
	 * @param survey
	 */
	void saveOrUpdate(AccessControlApplicationMap map);

}
