package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.User;

public interface AccessGroupService {

	/**
	 * 
	 * @return
	 */
	List<AccessGroup> loadAll();

	/**
	 * 
	 * @param groupId
	 * @return
	 */
	AccessGroup loadGroup(int groupId);
	
	/**
	 * 
	 * @param name
	 * @return
	 */
	AccessGroup loadGroup(String name);

	/**
	 * 
	 * @param group
	 */
	void storeGroup(AccessGroup group);

	/**
	 * 
	 * @param group
	 */
	void deactivateGroup(AccessGroup group);

	/**
	 * 
	 * @param userId
	 * @param groupIds
	 */
	void addGroupsToUser(Integer userId, List<Integer> groupIds);

	/**
	 * 
	 * @param groupId
	 * @param userIds
	 */
	void addUsersToGroup(Integer groupId, List<Integer> userIds);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	List<AccessGroup> getGroupsForUser(int userId);

	/**
	 * 
	 * @param groupId
	 * @return
	 */
	List<User> getUsersForGroup(int groupId);

	/**
	 * 
	 * @param user
	 * @param organization
	 * @return
	 */
	boolean hasAccess(int userId, Organization organization);
	
	void validate(AccessGroup accessGroup, BindingResult result);
}
