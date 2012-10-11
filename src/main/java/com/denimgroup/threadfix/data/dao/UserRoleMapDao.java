package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserRoleMap;

public interface UserRoleMapDao {

	/**
	 * @return
	 */
	List<UserRoleMap> retrieveAll();

	/**
	 * @param id
	 * @return
	 */
	UserRoleMap retrieveById(int id);
	
	/**
	 * @param survey
	 */
	void saveOrUpdate(UserRoleMap role);
	
	/**
	 * 
	 * @param roleId
	 * @return
	 */
	List<User> getUsersForRole(int roleId);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	List<Role> getRolesForUser(int userId);

	/**
	 * Careful: This method may return an inactive map.
	 * @param id
	 * @return
	 */
	UserRoleMap retrieveByUserAndRole(int userId, int roleId);
	
	/**
	 * 
	 * @return
	 */
	List<UserRoleMap> retrieveByRoleName(String roleName);
	
}
