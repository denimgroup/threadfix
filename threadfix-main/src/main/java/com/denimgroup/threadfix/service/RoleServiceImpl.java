package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.Role;

@Service
public class RoleServiceImpl implements RoleService {
	
	protected final SanitizedLogger log = new SanitizedLogger(RoleServiceImpl.class);
	
	private RoleDao roleDao;
	private UserDao userDao;
	
	@Autowired
	public RoleServiceImpl(RoleDao roleDao, UserDao userDao) {
		this.roleDao = roleDao;
		this.userDao = userDao;
	}

	@Override
	public List<Role> loadAll() {
		return roleDao.retrieveAll();
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
			return "A role with this name already exists.";
		}
		
		if (name.length() > Role.NAME_LENGTH) {
			return "The maximum length for name is " + Role.NAME_LENGTH + " characters.";
		}
		
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
