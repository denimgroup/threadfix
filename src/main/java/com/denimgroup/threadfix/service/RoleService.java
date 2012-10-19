package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;

public interface RoleService {

	/**
	 * 
	 * @param role
	 */
	void validateRole(Role role, BindingResult result);
	
	/**
	 * 
	 * @return
	 */
	List<Role> loadAll();
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	Role loadRole(int id);
	
	/**
	 * 
	 * @param name
	 * @return
	 */
	Role loadRole(String name);

	/**
	 * 
	 * @param id
	 */
	void deactivateRole(int id);
	
	/**
	 * 
	 * @param role
	 */
	void storeRole(Role role);

	/**
	 * 
	 * @param userId
	 * @return
	 */
	List<Role> getRolesForUser(int userId);

	/**
	 * 
	 * @param userId
	 * @param objectIds
	 */
	void setRolesForUser(Integer userId, List<Integer> roleIds);

	/**
	 * 
	 * @param roleId
	 * @return
	 */
	List<User> getUsersForRole(int roleId);

	/**
	 * 
	 * @param roleId
	 * @param objectIds
	 */
	void setUsersForRole(Integer roleId, List<Integer> userIds);

	/**
	 * We need to avoid a state where no users can perform administrative functions
	 * and the system becomes unusable.
	 * @param role
	 * @return
	 */
	boolean canDelete(Role role);
	
}
