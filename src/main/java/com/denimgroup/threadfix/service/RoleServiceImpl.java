package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.UserRoleMapDao;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserRoleMap;

@Service
public class RoleServiceImpl implements RoleService {
	
	protected final SanitizedLogger log = new SanitizedLogger(RoleServiceImpl.class);
	
	private RoleDao roleDao;
	private UserDao userDao;
	private UserRoleMapDao userRoleMapDao;
	
	@Autowired
	public RoleServiceImpl(UserRoleMapDao userRoleMapDao,
			RoleDao roleDao, UserDao userDao) {
		this.roleDao = roleDao;
		this.userDao = userDao;
		this.userRoleMapDao = userRoleMapDao;
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
		if (role != null) {
			role.setActive(false);
			
			if (role.getUserRoleMaps() != null && role.getUserRoleMaps().size() > 0) {
				for (UserRoleMap map : role.getUserRoleMaps()) {
					if (map != null) {
						deactivateMap(map);
					}
				}
			}
			
			// This deactivates all the maps
			setUsersForRole(id, new ArrayList<Integer>());
			roleDao.saveOrUpdate(role);
		}
	}

	@Override
	public void validateRole(Role role, BindingResult result) {
	}

	@Override
	@Transactional(readOnly = false)
	public void storeRole(Role role) {
		roleDao.saveOrUpdate(role);
	}

	@Override
	public List<Role> getRolesForUser(int userId) {
		return userRoleMapDao.getRolesForUser(userId);
	}

	@Override
	public List<User> getUsersForRole(int roleId) {
		return userRoleMapDao.getUsersForRole(roleId);
	}

	@Override
	@Transactional(readOnly = false)
	public void setRolesForUser(Integer userId, List<Integer> roleIds) {
		log.info("Adding roles (" + roleIds + ") to user with ID " + userId + ".");
		
		Set<Integer> idsToAdd = new HashSet<Integer>();
		
		if (roleIds != null && roleIds.size() != 0) {
			idsToAdd.addAll(roleIds);
		}

		User user = userDao.retrieveById(userId);
		if (user != null) {
			// Role to map
			
			if (user.getUserRoleMaps() != null) {
				for (UserRoleMap map : user.getUserRoleMaps()) {
					if (map.isActive() && map.getRole() != null &&
							map.getRole().getId() != null) {
						
						if (!idsToAdd.contains(map.getRole().getId())) {
							log.info("Removing role " + map.getRole().getId() + " from user " + user.getId());
							deactivateMap(map);
						} else {
							idsToAdd.remove(map.getRole().getId());
						}
					}
				}
			}
			
			for (Integer id : idsToAdd) {
				Role role = roleDao.retrieveById(id);
				if (role != null) {
					activateMap(user, role);
				}
			}
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void setUsersForRole(Integer roleId, List<Integer> userIds) {
		log.info("Adding users (" + userIds + ") to role with ID " + roleId + ".");
		
		Set<Integer> idsToAdd = new HashSet<Integer>();
		
		if (userIds != null && userIds.size() != 0) {
			idsToAdd.addAll(userIds);
		}

		Role role = roleDao.retrieveById(roleId);
		if (role != null) {

			if (role.getUserRoleMaps() != null) {
				for (UserRoleMap map : role.getUserRoleMaps()) {
					if (map.isActive() && map.getUser() != null &&
							map.getUser().getId() != null) {
						
						if (!idsToAdd.contains(map.getUser().getId())) {
							log.info("Removing role " + map.getUser().getId() + " from user " + role.getId());
							deactivateMap(map);
						} else {
							idsToAdd.remove(map.getUser().getId());
						}
					}
				}
			}
			
			for (Integer id : idsToAdd) {
				User user = userDao.retrieveById(id);
				if (role != null) {
					activateMap(user, role);
				}
			}
		}
	}
	
	private void deactivateMap(UserRoleMap map) {
		map.setActive(false);
		userRoleMapDao.saveOrUpdate(map);
	}
	
	private void activateMap(User user, Role role) {
		if (user == null || role == null) {
			return;
		}
		
		UserRoleMap map = userRoleMapDao.retrieveByUserAndRole(user.getId(), role.getId());
	
		if (map == null) {
			UserRoleMap newMap = new UserRoleMap();
			newMap.setUser(user);
			newMap.setRole(role);
			userRoleMapDao.saveOrUpdate(newMap);
		} else {
			map.setActive(true);
			userRoleMapDao.saveOrUpdate(map);
		}
	}

}
