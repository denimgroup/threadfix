package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserGroupMap;

public interface UserGroupMapDao {

	/**
	 * @return
	 */
	List<UserGroupMap> retrieveAll();

	/**
	 * @param id
	 * @return
	 */
	UserGroupMap retrieveById(int id);
	
	/**
	 * @param survey
	 */
	void saveOrUpdate(UserGroupMap group);
	
	/**
	 * 
	 * @param groupId
	 * @return
	 */
	List<User> getUsersForGroup(int groupId);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	List<AccessGroup> getGroupsForUser(int userId);

	/**
	 * Careful: This method may return an inactive map.
	 * @param id
	 * @return
	 */
	UserGroupMap retrieveByUserAndGroup(int userId, int groupId);
	
}
