////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.util.List;

@Service
public class RoleServiceImpl implements RoleService {
	
	protected final SanitizedLogger log = new SanitizedLogger(RoleServiceImpl.class);
	
	@Autowired
	private RoleDao roleDao;
	@Autowired
	private UserDao userDao;

	@Override
	@Transactional
	public List<Role> loadAll() {
		return roleDao.retrieveAll();
	}

	@Override
	@Transactional
	public List<Role> loadAllWithCanDeleteSet() {
		List<Role> roles = roleDao.retrieveAll();

		for (Role role : roles) {
			role.setCanDelete(canDelete(role));
		}

		return roles;
	}

	@Override
	@Transactional
	public Role loadRole(int id) {
		return roleDao.retrieveById(id);
	}

	@Override
	public Role loadRole(String name) {
		return roleDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateRole(int id) {
		Role role = loadRole(id);
		if (role != null && canDelete(role)) {
			role.setActive(false);

            for (User user : role.getUsers()) {
                user.setGlobalRole(null);
                user.setHasGlobalGroupAccess(false);
                userDao.saveOrUpdate(user);
            }

			// This deactivates all the maps
			roleDao.saveOrUpdate(role);
		}
	}
	
	@Override
	public boolean canDelete(Role role) {
		boolean canDelete = true;
		
		if (role.getCanManageUsers() &&
			!userDao.canRemovePermissionFromRole(role.getId(), "canManageUsers")) {
			canDelete = false;
		}
		
		if (canDelete && role.getCanManageRoles() && 
				!userDao.canRemovePermissionFromRole(role.getId(), "canManageRoles")) {
			canDelete = false;
		}
		
		return canDelete;
	}

	@Override
	public String validateRole(Role role, BindingResult result) {
		if (result.hasFieldErrors("displayName")) {
			return FIELD_ERROR;
		}
		
		String name = role.getDisplayName();

		if (name == null || name.trim().length() == 0) {
			result.rejectValue("displayName", null, null, "This field cannot be blank");
			return FIELD_ERROR;
		}
		
		Role databaseRole = loadRole(name.trim());
		
		if (databaseRole != null && !databaseRole.getId().equals(role.getId())) {
            result.rejectValue("displayName", MessageConstants.ERROR_NAMETAKEN);
			return FIELD_ERROR;
		}
		
		if (name.length() > Role.NAME_LENGTH) {
			return FIELD_ERROR;
		}

		databaseRole = role.getId() == null ? null : loadRole(role.getId());
		if (databaseRole != null) {
			if (databaseRole.getCanManageUsers() && !role.getCanManageUsers() && 
					!userDao.canRemovePermissionFromRole(role.getId(), "canManageUsers")) {
				return "You cannot remove the Manage Users privilege from this role.";
			}
			
			if (databaseRole.getCanManageRoles() && !role.getCanManageRoles() && 
					!userDao.canRemovePermissionFromRole(role.getId(), "canManageRoles")) {
				return "You cannot remove the Manage Roles privilege from this role.";
			}
		}
		
		return SUCCESS;
	}

	@Override
	@Transactional(readOnly = false)
	public void storeRole(Role role) {
		roleDao.saveOrUpdate(role);
	}
}
