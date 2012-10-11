package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.Role;

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
	
}
