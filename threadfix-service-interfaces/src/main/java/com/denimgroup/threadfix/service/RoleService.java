package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.Role;

public interface RoleService {
	
	// TODO switch to a bean or enum return
	public static final String SUCCESS = "Success";
	public static final String FIELD_ERROR = "Field Error";

	/**
	 * 
	 * @param role
	 */
	String validateRole(Role role, BindingResult result);
	
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
	 * We need to avoid a state where no users can perform administrative functions
	 * and the system becomes unusable.
	 * @param role
	 * @return
	 */
	boolean canDelete(Role role);
	
}
