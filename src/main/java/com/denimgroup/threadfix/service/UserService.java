////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;

/**
 * @author bbeverly
 * 
 */
public interface UserService {

	/**
	 * @return
	 */
	List<User> loadAllUsers();

	/**
	 * @param userId
	 * @return
	 */
	User loadUser(int userId);

	/**
	 * @param name
	 * @return
	 */
	User loadUser(String name);

	/**
	 * @param user
	 */
	void storeUser(User user);

	/**
	 * @param userId
	 */
	void delete(User user);

	/**
	 * @param user
	 */
	void createUser(User user);

	/**
	 * @return
	 */
	List<Role> loadAllRoles();

	/**
	 * @param roleId
	 * @return
	 */
	Role loadRole(int roleId);

	/**
	 * @param name
	 * @return
	 */
	Role loadRole(String name);

	/**
	 * @param role
	 */
	void storeRole(Role role);
	
	/**
	 * 
	 * @param user
	 * @param password
	 * @return
	 */
	boolean isCorrectPassword(User user, String password);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	Set<Permission> getGlobalPermissions(Integer userId);

	/**
	 * We can't allow a user to be deleted if it would leave the system with no users that could
	 * perform administrative functions. This method checks to see if that would happen.
	 * @param user
	 * @return
	 */
	boolean canDelete(User user);

	/**
	 * 
	 * @param userId
	 * @param objectIds
	 * @return
	 */
	boolean canSetRoles(int userId, List<Integer> objectIds);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	Map<Integer, Set<Permission>> getApplicationPermissions(Integer userId);
	
	/**
	 * 
	 * @param userId
	 * @return
	 */
	Map<Integer, Set<Permission>> getOrganizationPermissions(Integer userId);
}
