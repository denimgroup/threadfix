package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.entities.Role;

@Service
public class RoleServiceImpl implements RoleService {
	
	private RoleDao roleDao;
	
	@Autowired
	public RoleServiceImpl(RoleDao roleDao) {
		this.roleDao = roleDao;
	}

	@Override
	public List<Role> loadAll() {
		return roleDao.retrieveAll();
	}

	@Override
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
		role.setActive(false);
		roleDao.saveOrUpdate(role);
	}

	@Override
	public void validateRole(Role role, BindingResult result) {
	}

	@Override
	@Transactional(readOnly = false)
	public void storeRole(Role role) {
		roleDao.saveOrUpdate(role);
	}

}
