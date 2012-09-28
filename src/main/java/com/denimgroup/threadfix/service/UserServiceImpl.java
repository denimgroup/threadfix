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
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;

@Service
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {
	
	private final Log log = LogFactory.getLog("UserService");

	private UserDao userDao = null;
	private RoleDao roleDao = null;

	private ThreadFixPasswordEncoder encoder = new ThreadFixPasswordEncoder();

	@Autowired
	public UserServiceImpl(UserDao userDao, RoleDao roleDao) {
		this.userDao = userDao;
		this.roleDao = roleDao;
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
		user.setName(user.getName() + new Date().toString());
		if (user.getName().length() > User.NAME_LENGTH) {
			user.setName(user.getName().substring(0, User.NAME_LENGTH - 1));
		}
		user.setActive(false);
		userDao.saveOrUpdate(user);
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
	
	@Override
	public Long countActiveAdmins() {
		return userDao.countActiveAdmins();
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
	public boolean isAdmin(User user) {
		boolean test = user != null && user.getRole() != null && 
				user.getRole().getId() != null && 
				roleDao.isAdmin(user.getRole().getId());
		
		return test;
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
}