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

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.UserGroupMapDao;
import com.denimgroup.threadfix.data.dao.UserRoleMapDao;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserGroupMap;
import com.denimgroup.threadfix.data.entities.UserRoleMap;

@Service
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {

	protected final SanitizedLogger log = new SanitizedLogger(UserService.class);

	private UserDao userDao = null;
	private RoleDao roleDao = null;
	private UserRoleMapDao userRoleMapDao = null;
	private UserGroupMapDao userGroupMapDao = null;

	private ThreadFixPasswordEncoder encoder = new ThreadFixPasswordEncoder();

	@Autowired
	public UserServiceImpl(UserDao userDao, RoleDao roleDao, 
			UserRoleMapDao userRoleMapDao, UserGroupMapDao userGroupMapDao) {
		this.userDao = userDao;
		this.roleDao = roleDao;
		this.userRoleMapDao = userRoleMapDao;
		this.userGroupMapDao = userGroupMapDao;
	}

	@Override
	public List<User> loadAllUsers() {
		return userDao.retrieveAllActive();
	}

	@Override
	public User loadUser(int userId) {
		return userDao.retrieveById(userId);
	}

	@Override
	public User loadUser(String name) {
		return userDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeUser(User user) {
		if ((user.getUnencryptedPassword() != null) && (user.getUnencryptedPassword().length() > 0)) {
			encryptPassword(user);
		}
		userDao.saveOrUpdate(user);
	}

	@Override
	@Transactional(readOnly = false)
	public void delete(User user) {
		if (user != null) {
			user.setName(user.getName() + new Date().toString());
			if (user.getName().length() > User.NAME_LENGTH) {
				user.setName(user.getName().substring(0, User.NAME_LENGTH - 1));
			}

			if (user.getUserGroupMaps() != null && !user.getUserGroupMaps().isEmpty()) {
				for (UserGroupMap map : user.getUserGroupMaps()) {
					map.setActive(false);
					userGroupMapDao.saveOrUpdate(map);
				}
			}

			if (user.getUserRoleMaps() != null && !user.getUserRoleMaps().isEmpty()) {
				for (UserRoleMap map : user.getUserRoleMaps()) {
					map.setActive(false);
					userRoleMapDao.saveOrUpdate(map);
				}
			}

			user.setActive(false);
			userDao.saveOrUpdate(user);
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void createUser(User user) {
		encryptPassword(user);
		userDao.saveOrUpdate(user);
	}

	@Override
	public List<Role> loadAllRoles() {
		return roleDao.retrieveAll();
	}

	@Override
	public Role loadRole(int roleId) {
		return roleDao.retrieveById(roleId);
	}

	@Override
	public Role loadRole(String name) {
		return roleDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeRole(Role role) {
		roleDao.saveOrUpdate(role);
	}

	private void encryptPassword(User user) {
		try {
			user.setSalt(encoder.generateSalt());
			user.setPassword(encoder.generatePasswordHash(user.getUnencryptedPassword(),
					user.getSalt()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean isCorrectPassword(User user, String password) {
		if (user.getPassword() != null && user.getSalt() != null 
				&& password != null) {
			try {
				String encodedPassword = encoder.generatePasswordHash(password, user.getSalt());
				return encodedPassword != null && encodedPassword.equals(user.getPassword());
			} catch (NoSuchAlgorithmException e) {
				// This should never happen but let's log it
				log.warn("Failed to encrypt a password - something is broken.", e);
			}
		} 

		return false;
	}

	@Override
	public Set<Permission> getPermissions(Integer userId) {
		Set<Permission> returnList = new HashSet<Permission>();

		if (userId != null) {
			List<Role> roles = userRoleMapDao.getRolesForUser(userId);
			if (roles != null) {
				for (Role role: roles) {
					returnList.addAll(role.getPermissions());
				}
			}
		}

		return returnList;
	}

	@Override
	public boolean canDelete(User user) {
		boolean canDelete = true;
		
		Set<Permission> permissions = getPermissions(user.getId());

		if (canDelete && permissions.contains(Permission.CAN_MANAGE_USERS) && 
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageUsers")) {
			canDelete = false;
		}

		if (canDelete && permissions.contains(Permission.CAN_MANAGE_GROUPS) && 
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageGroups")) {
			canDelete = false;
		}

		if (canDelete && permissions.contains(Permission.CAN_MANAGE_ROLES) && 
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageRoles")) {
			canDelete = false;
		}
		
		return canDelete;
	}
	
	@Override
	public boolean canSetRoles(int userId, List<Integer> objectIds) {
		boolean canSetRoles = true;
		
		Set<Permission> oldPermissions = getPermissions(userId);
		Set<Permission> newPermissions = new HashSet<Permission>();
		
		if (objectIds != null) {
			for (Integer integer : objectIds) {
				Role role = roleDao.retrieveById(integer);
				
				if (role != null) {
					newPermissions.addAll(role.getPermissions());
				}
			}
		}
		
		if (canSetRoles && oldPermissions.contains(Permission.CAN_MANAGE_USERS) &&
				!newPermissions.contains(Permission.CAN_MANAGE_USERS) &&
				!userDao.canRemovePermissionFromUser(userId, "canManageUsers")) {
			canSetRoles = false;
		}
		
		if (canSetRoles && oldPermissions.contains(Permission.CAN_MANAGE_GROUPS) &&
				!newPermissions.contains(Permission.CAN_MANAGE_GROUPS) &&
				!userDao.canRemovePermissionFromUser(userId, "canManageGroups")) {
			canSetRoles = false;
		}
		
		if (canSetRoles && oldPermissions.contains(Permission.CAN_MANAGE_ROLES) &&
				!newPermissions.contains(Permission.CAN_MANAGE_ROLES) &&
				!userDao.canRemovePermissionFromUser(userId, "canManageRoles")) {
			canSetRoles = false;
		}
		
		return canSetRoles;
	}
}
