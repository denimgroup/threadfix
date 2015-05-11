////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.User;

import java.util.List;

/**
 * Basic DAO class for the User entity.
 * 
 * @author dshannon
 */
public interface UserDao extends GenericNamedObjectDao<User> {
	
	/**
	 * @param name
	 * @return
	 */
	User retrieveLdapUser(String name);

	/**
	 * Checks to see whether it's ok to delete the role with the given id based on whether
	 * a user will still have the given permission.
	 * @param id
	 * @param string
	 * @return
	 */
	boolean canRemovePermissionFromRole(Integer id, String string);

	/**
	 * Checks to see whether it's ok to delete the user with the given id based on whether
	 * a user will still have the given permission.
	 * @param id
	 * @param string
	 * @return
	 */
	boolean canRemovePermissionFromUser(Integer id, String string);
	
	/**
	 * 
	 * @param orgId
	 * @return
	 */
	List<User> retrieveOrgPermissibleUsers(Integer orgId);
	
	/**
	 * 
	 * @param orgId
	 * @param appId 
	 * @return
	 */
	List<User> retrieveAppPermissibleUsers(Integer orgId, Integer appId);


	/**
	 * Return users by specified page
	 * @param page
	 * @param numberToShow
	 * @return
	 */
	List<User> retrievePage(int page, int numberToShow);

	/**
	 * Return total number of users in system
	 * @return
	 * @param searchString
	 */
	Long countUsers(String searchString);

	boolean canRemovePermissionFromUserAndGroup(Integer userId, Integer groupId, String camelCase);

	List<User> getSearchResults(String searchString, int number, int page);
}
