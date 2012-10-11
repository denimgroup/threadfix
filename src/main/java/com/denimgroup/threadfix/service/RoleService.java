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
	public void validateRole(Role role, BindingResult result);
	
	/**
	 * 
	 * @return
	 */
	public List<Role> loadAll();
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	public Role loadRole(int id);
	
	/**
	 * 
	 * @param name
	 * @return
	 */
	public Role loadRole(String name);

	/**
	 * 
	 * @param id
	 */
	public void deactivateRole(int id);
	
	/**
	 * 
	 * @param role
	 */
	public void storeRole(Role role);

	/**
	 * 
	 * @param userId
	 * @return
	 */
	public List<Role> getRolesForUser(int userId);

	/**
	 * 
	 * @param userId
	 * @param objectIds
	 */
	public void setRolesForUser(Integer userId, List<Integer> roleIds);

	/**
	 * 
	 * @param roleId
	 * @return
	 */
	public List<User> getUsersForRole(int roleId);

	/**
	 * 
	 * @param roleId
	 * @param objectIds
	 */
	public void setUsersForRole(Integer roleId, List<Integer> userIds);
	
}
