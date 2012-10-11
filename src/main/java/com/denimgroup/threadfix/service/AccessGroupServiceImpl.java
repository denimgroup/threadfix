package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.AccessGroupDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.UserGroupMapDao;
import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserGroupMap;

@Service
@Transactional(readOnly = true)
public class AccessGroupServiceImpl implements AccessGroupService {

	protected final SanitizedLogger log = new SanitizedLogger(AccessGroupService.class);

	private AccessGroupDao accessGroupDao = null;
	private UserDao userDao = null;
	private UserGroupMapDao userGroupMapDao = null;
	private OrganizationDao organizationDao = null;

	@Autowired
	public AccessGroupServiceImpl(AccessGroupDao groupDao,
			UserDao userDao, 
			OrganizationDao organizationDao,
			UserGroupMapDao userGroupMapDao) {
		this.accessGroupDao = groupDao;
		this.userDao = userDao;
		this.organizationDao = organizationDao;
		this.userGroupMapDao = userGroupMapDao;
	}

	@Override
	public List<AccessGroup> loadAll() {
		return accessGroupDao.retrieveAll();
	}

	@Override
	public AccessGroup loadGroup(int groupId) {
		return accessGroupDao.retrieveById(groupId);
	}
	
	@Override
	public AccessGroup loadGroup(String name) {		
		return accessGroupDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeGroup(AccessGroup group) {
		accessGroupDao.saveOrUpdate(group);
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateGroup(AccessGroup group) {
		log.info("Deleting Group with id " + group.getId());
		
		group.setActive(false);
		
		for (UserGroupMap map : group.getUserGroupMaps()) {
			map.setActive(false);
			userGroupMapDao.saveOrUpdate(map);
		}
		
		accessGroupDao.saveOrUpdate(group);
	}

	@Override
	public void setGroupsForUser(Integer userId, List<Integer> groupIds) {
		log.info("Adding groups (" + groupIds + ") to user with ID " + userId + ".");
		
		Set<Integer> idsToAdd = new HashSet<Integer>();
		
		if (groupIds != null && groupIds.size() != 0) {
			idsToAdd.addAll(groupIds);
		}

		User user = userDao.retrieveById(userId);
		if (user != null) {
			// Group to map
			
			if (user.getUserGroupMaps() != null) {
				for (UserGroupMap map : user.getUserGroupMaps()) {
					if (map.isActive() && map.getAccessGroup() != null &&
							map.getAccessGroup().getId() != null) {
						
						if (!idsToAdd.contains(map.getAccessGroup().getId())) {
							log.info("Removing group " + map.getAccessGroup().getId() + " from user " + user.getId());
							deactivateMap(map);
						} else {
							idsToAdd.remove(map.getAccessGroup().getId());
						}
					}
				}
			}
			
			for (Integer id : idsToAdd) {
				AccessGroup group = accessGroupDao.retrieveById(id);
				if (group != null) {
					activateMap(user, group);
				}
			}
		}
	}
	
	@Override
	public void setUsersForGroup(Integer groupId, List<Integer> userIds) {
		log.info("Adding users (" + userIds + ") to group with ID " + groupId + ".");
		
		Set<Integer> idsToAdd = new HashSet<Integer>();
		
		if (userIds != null && userIds.size() != 0) {
			idsToAdd.addAll(userIds);
		}

		AccessGroup group = accessGroupDao.retrieveById(groupId);
		if (group != null) {

			if (group.getUserGroupMaps() != null) {
				for (UserGroupMap map : group.getUserGroupMaps()) {
					if (map.isActive() && map.getUser() != null &&
							map.getUser().getId() != null) {
						
						if (!idsToAdd.contains(map.getUser().getId())) {
							log.info("Removing group " + map.getUser().getId() + " from user " + group.getId());
							deactivateMap(map);
						} else {
							idsToAdd.remove(map.getUser().getId());
						}
					}
				}
			}
			
			for (Integer id : idsToAdd) {
				User user = userDao.retrieveById(id);
				if (group != null) {
					activateMap(user, group);
				}
			}
		}
	}
	
	private void deactivateMap(UserGroupMap map) {
		map.setActive(false);
		userGroupMapDao.saveOrUpdate(map);
	}
	
	private void activateMap(User user, AccessGroup group) {
		if (user == null || group == null) {
			return;
		}
		
		UserGroupMap map = userGroupMapDao.retrieveByUserAndGroup(user.getId(), group.getId());
	
		if (map == null) {
			UserGroupMap newMap = new UserGroupMap();
			newMap.setUser(user);
			newMap.setAccessGroup(group);
			userGroupMapDao.saveOrUpdate(newMap);
		} else {
			map.setActive(true);
			userGroupMapDao.saveOrUpdate(map);
		}
	}
	
	@Override
	public List<User> getUsersForGroup(int groupId) {
		return userGroupMapDao.getUsersForGroup(groupId);
	}

	@Override
	public List<AccessGroup> getGroupsForUser(int userId) {
		return userGroupMapDao.getGroupsForUser(userId);
	}
	
	@Override
	public boolean hasAccess(int userId, Organization organization) {
		List<AccessGroup> groups = getGroupsForUser(userId);
		
		return orgIdInGroups(organization.getId(), groups, new HashSet<Integer>());
	}
	
	/**
	 * Basic recursion to traverse the group tree.<br>
	 * The set is to prevent cyclic recursion.
	 * @param orgId
	 * @param groups
	 * @param checkedIds
	 * @return
	 */
	private boolean orgIdInGroups(int orgId, List<AccessGroup> groups, Set<Integer> checkedIds) {
		if (groups == null || groups.size() == 0) {
			return false;
		}
		
		for (AccessGroup group : groups) {
			if (group == null || group.getId() == null ||
					checkedIds.contains(group.getId())) {
				continue;
			} else {
				checkedIds.add(group.getId());
			}
			
			if (group.getTeam() != null && orgId == group.getTeam().getId()) {
				return true;
			} else {
				if (orgIdInGroups(orgId, group.getChildGroups(), checkedIds)) {
					return true;
				}
			}
		}
		
		return false;
	}

	@Override
	public void validate(AccessGroup accessGroup, BindingResult result) {

		if (!hasValidParentGroup(accessGroup)){
			accessGroup.setParentGroup(null);
		} 
		
		if (!hasValidTeam(accessGroup)) {
			accessGroup.setTeam(null);
		}

		if (result.getFieldError("parentGroup.id") == null &&
				hasCycle(accessGroup)) {
			result.rejectValue("parentGroup.id", null, null, "Choose another group. This one leads to a cycle.");
		}
		
		String error = getNameError(accessGroup.getName(), accessGroup.getId());
		
		if (error != null)
			result.rejectValue("name", null, null, error);
	}
	
	private boolean hasCycle(AccessGroup accessGroup) {
		
		if (accessGroup == null || accessGroup.getId() == null
				|| accessGroup.getParentGroup() == null) {
			return false;
		}
		
		AccessGroup dbGroup = loadGroup(accessGroup.getId());
		
		AccessGroup parentGroup = loadGroup(accessGroup.getParentGroup().getId());
		
		// This should be caught elsewhere. if dbGroup == null then it's a new instance
		// new instances cannot lead to cycles because they cannot have children
		if (dbGroup == null || parentGroup == null) {
			return false;
		}
		
		accessGroup.setChildGroups(dbGroup.getChildGroups());
		
		if (parentGroup.getChildGroups() == null) {
			parentGroup.setChildGroups(new ArrayList<AccessGroup>());
		}
		
		if (!parentGroup.getChildGroups().contains(dbGroup)) {
			parentGroup.getChildGroups().add(accessGroup);
		}
		
		
		Set<Integer> ids = new HashSet<Integer>();
		ids.add(parentGroup.getId());
		
		return hasCycleRecursive(parentGroup.getChildGroups(), ids);
	}
	
	private boolean hasCycleRecursive(List<AccessGroup> groups, Set<Integer> seenIds) {
		if (groups != null && groups.size() != 0) {
			for (AccessGroup group : groups) {
				if (group == null || !group.isActive()) 
					continue;
				
				if (seenIds.contains(group.getId()))
					return true;
				else
					seenIds.add(group.getId());
				
				if (hasCycleRecursive(group.getChildGroups(), seenIds))
					return true;
			}
		}
		
		return false;
	}

	private boolean hasValidParentGroup(AccessGroup group) {
		return group.getParentGroup() != null &&
				group.getParentGroup().getId() != null &&
				loadGroup(group.getParentGroup().getId()) != null;
	}
	
	private boolean hasValidTeam(AccessGroup group) {
		return group.getTeam() != null && 
				group.getTeam().getId() != null &&
				organizationDao.retrieveById(group.getTeam().getId()) != null;
	}
	
	private String getNameError(String name, Integer currentId) {
		String error = null;

		if (name == null || name.trim().length() == 0) {
			error = "This field cannot be blank";
		}
		
		AccessGroup group = loadGroup(name.trim());
		
		if (group != null && !group.getId().equals(currentId)) {
			error = "A group with this name already exists.";
		}
		
		if (name.length() > AccessGroup.NAME_LENGTH) {
			error = "The maximum length for name is " + AccessGroup.NAME_LENGTH + " characters.";
		}
		
		return error;
	}
}
