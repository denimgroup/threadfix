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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.AccessControlMapDao;
import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.UserEventNotificationMapDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.importer.util.IntegerUtils.getIntegerOrNull;

@Service
public class UserServiceImpl implements UserService {

    protected final SanitizedLogger log = new SanitizedLogger(UserService.class);

    @Autowired
    private UserDao             userDao             = null;
    @Autowired
    private RoleDao             roleDao             = null;
    @Autowired
    private AccessControlMapDao accessControlMapDao = null;
	@Autowired
	private APIKeyService apiKeyService;
	@Autowired
	private UserEventNotificationMapDao userEventNotificationMapDao = null;

    private ThreadFixPasswordEncoder encoder = new ThreadFixPasswordEncoder();

	private static final SanitizedLogger LOG = new SanitizedLogger(UserServiceImpl.class);

    /**
     * Transactional(readOnly = false) here means that false will be put in to
     * the LDAP user field and update correctly.
     */
    @Override
    @Transactional(readOnly = false)
    public List<User> loadAllUsers() {
        return userDao.retrieveAllActive();
    }

    @Override
    public User getCurrentUser() {
		User user = null;

		SecurityContext context = SecurityContextHolder.getContext();
		if (context != null) {
			Authentication authentication = context.getAuthentication();
			if (authentication != null) {
				Object principal = authentication.getPrincipal();

				if (principal instanceof ThreadFixUserDetails) {

					ThreadFixUserDetails details = (ThreadFixUserDetails) principal;

					Integer userId = details.getUserId();

					user = userDao.retrieveById(userId);
				}
			}
		}

        return user;
    }

    @Override
    @Transactional(readOnly = false) // used to be true
    public User loadUser(int userId) {
        return userDao.retrieveById(userId);
    }

    @Override
    @Transactional(readOnly = false)
    public List<User> loadUsers(String name) {
        List<User> users = list();
        User localUser = userDao.retrieveLocalUser(name);
        User ldapUser = userDao.retrieveLdapUser(name);
        if (localUser != null)
            users.add(localUser);
        if (ldapUser != null)
            users.add(ldapUser);
        return users;
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

			if (user.getApiKeys() != null) {
				for (APIKey key : user.getApiKeys()) {
					key.setActive(false);
					apiKeyService.storeAPIKey(key);
				}
			}

            user.setActive(false);
            userDao.saveOrUpdate(user);
        }
    }

    @Override
    @Transactional(readOnly = false)
    public Integer createUser(User user) {
        initializeUserEventNotificationMaps(user);
        encryptPassword(user);
        userDao.saveOrUpdate(user);
        return user.getId();
    }

    private void initializeUserEventNotificationMaps(User user) {
		Set<EventAction> eventNotificationTypes = EnumSet.copyOf(EventAction.globalEventActions);
		eventNotificationTypes.addAll(EventAction.globalGroupedEventActions);

		setNotificationEventActions(user, eventNotificationTypes);

		user.setUserEventNotificationMapsInitialized(true);
	}

    private void encryptPassword(User user) {
        user.setSalt(encoder.generateSalt());
        user.setPassword(encoder.encodePassword(user.getUnencryptedPassword(),
                user.getSalt()));
	}

	@Override
	@Transactional(readOnly = false) // used to be true
	public boolean isCorrectPassword(User user, String password) {
		if (user.getPassword() != null && user.getSalt() != null 
				&& password != null) {
			return encoder.isPasswordValid(user.getPassword(), password, user.getSalt());
		}

		return false;
	}

	@Override
	@Transactional(readOnly = false) // used to be true
	public Set<Permission> getGlobalPermissions(Integer userId) {
		Set<Permission> returnList = set();

		User user = loadUser(userId);

		if (user != null && user.getHasGlobalGroupAccess()) {
			returnList.add(Permission.READ_ACCESS); // true even in the case user has Global Read Access role
			if (user.getGlobalRole() != null)
				returnList.addAll(user.getGlobalRole().getPermissions());
		}

		returnList.addAll(getGroupPermissions(userId));

		return returnList;
	}

	public Set<Permission> getGroupPermissions(Integer userId) {
		Set<Permission> returnList = set();

		User user = loadUser(userId);

		if (user != null && user.getGroups() != null && user.getGroups().size() != 0) {
			for (Group group : user.getGroups()) {
				if (group.isActive() && group.getHasGlobalAccess()) {
					returnList.add(Permission.READ_ACCESS);
				}

				if (group.isActive() && group.getGlobalRole() != null) {
					returnList.addAll(group.getGlobalRole().getPermissions());
				}
			}
		}

		return returnList;
	}

	@Override
	@Transactional(readOnly = false) // used to be true
	public boolean canDelete(User user) {
		boolean canDelete = true;
		
		Set<Permission> permissions = getGlobalPermissions(user.getId());

		if (permissions.contains(Permission.CAN_MANAGE_USERS) &&
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageUsers")) {
			canDelete = false;
		}

		if (canDelete && permissions.contains(Permission.CAN_MANAGE_ROLES) && 
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageRoles")) {
			canDelete = false;
		}
		
		return canDelete;
	}

	@Override
	@Transactional(readOnly = false) // used to be true
	public boolean canRemoveAdminPermissions(User user) {
		boolean canRemove = true;

		Set<Permission>
				permissions      = getGlobalPermissions(user.getId()),
				groupPermissions = getGroupPermissions(user.getId());

		if (permissions.contains(Permission.CAN_MANAGE_USERS) &&
				!groupPermissions.contains(Permission.CAN_MANAGE_USERS) &&
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageUsers")) {
			canRemove = false;
		}

		if (canRemove && permissions.contains(Permission.CAN_MANAGE_ROLES) &&
				!groupPermissions.contains(Permission.CAN_MANAGE_ROLES) &&
				!userDao.canRemovePermissionFromUser(user.getId(), "canManageRoles")) {
			canRemove = false;
		}

		return canRemove;
	}



	@Override
	@Transactional(readOnly = false) // used to be true
	public Map<Integer, Set<Permission>> getApplicationPermissions(User user) {
		return getApplicationPermissions(getMapsForUser(user.getId()));
	}

    @Override
    @Transactional(readOnly = false) // used to be true
    public Map<Integer, Set<Permission>> getApplicationPermissions(List<AccessControlTeamMap> maps) {
        Map<Integer, Set<Permission>> applicationPermissions = new HashMap<>();

        for (AccessControlTeamMap teamMap : maps) {
            if (teamMap != null && teamMap.getAccessControlApplicationMaps() != null) {
                for (AccessControlApplicationMap appMap : teamMap.getAccessControlApplicationMaps()) {
                    if (appMap != null && appMap.isActive() &&
                            appMap.getApplication() != null &&
                            appMap.getApplication().getId() != null &&
                            appMap.getRole() != null &&
                            appMap.getRole().getPermissions() != null) {
                        applicationPermissions.put(appMap.getApplication().getId(),
                                appMap.getRole().getPermissions());
                        applicationPermissions.get(appMap.getApplication().getId()).add(Permission.READ_ACCESS);
                    }
                }
            }
        }

        return applicationPermissions;
    }

	@Override
	@Transactional(readOnly = false) // used to be true
	public Map<Integer, Set<Permission>> getOrganizationPermissions(User user) {
		return getOrganizationPermissions(getMapsForUser(user.getId()));
	}

    @Override
    @Transactional(readOnly = false) // used to be true
    public Map<Integer, Set<Permission>> getOrganizationPermissions(List<AccessControlTeamMap> maps) {
        Map<Integer, Set<Permission>> organizationPermissions = new HashMap<>();

        for (AccessControlTeamMap map : maps) {
            if (map != null && map.getOrganization() != null &&
                    map.getOrganization().getId() != null &&
                    map.getRole() != null &&
                    map.getRole().getPermissions() != null) {
                organizationPermissions.put(map.getOrganization().getId(),
                        map.getRole().getPermissions());
                organizationPermissions.get(map.getOrganization().getId()).add(Permission.READ_ACCESS);
            }
        }

        return organizationPermissions;
    }

	private List<AccessControlTeamMap> getMapsForUser(Integer userId) {
		List<AccessControlTeamMap> maps = list();

		User user = loadUser(userId);

		List<AccessControlTeamMap> userMaps = accessControlMapDao.retrieveAllMapsForUser(user.getId());

		if (userMaps != null) {
			maps.addAll(userMaps);
		}

		if (user.getGroups() != null) {
			for (Group group : user.getGroups()) {
				List<AccessControlTeamMap> tempMaps = accessControlMapDao.retrieveAllMapsForGroup(group.getId());
				if (tempMaps != null) {
					maps.addAll(tempMaps);
				}
			}
		}

		return maps;
	}

	@Override
	@Transactional(readOnly = false) // used to be true
	public boolean hasRemovedAdminPermissions(User user) {

        if (user == null || user.getId() == null) {
            return true; // should never get here
        }

        Set<Permission> dbPerms = getGlobalPermissions(user.getId());

        if (user.getGlobalRole() == null || user.getGlobalRole().getId() == null) {
            return dbPerms.contains(Permission.CAN_MANAGE_USERS) ||
                    dbPerms.contains(Permission.CAN_MANAGE_ROLES);
        }

        Role newRole = roleDao.retrieveById(user.getGlobalRole().getId());

        if (newRole == null) {
            return false;
        }

        Set<Permission> newPerms = newRole.getPermissions();

        return newPerms != null && (user.getGlobalRole() != null && (!newPerms.contains(Permission.CAN_MANAGE_USERS)
                && dbPerms.contains(Permission.CAN_MANAGE_USERS)) || (!newPerms.contains(Permission.CAN_MANAGE_ROLES)
                && dbPerms.contains(Permission.CAN_MANAGE_ROLES)));

    }

	@Override
	@Transactional(readOnly = false) // used to be true
	public User loadLdapUser(String name) {
		return userDao.retrieveLdapUser(name);
	}

    /**
     * @param name of user.
     * @return User by name.
     */
    @Override
    @Transactional(readOnly = false)
    public User loadLocalUser(String name) {
        return userDao.retrieveLocalUser(name);
    }


    // This is a terrible idea, we should switch to a strategy that
	// actually lets us use normal model validation
	@Override
	public User applyChanges(User user, Integer userId) {
		if (user == null || userId == null) {
			return null;
		}
		
		User returnUser = loadUser(userId);
		if (returnUser == null) {
			return null;
		}
		
//		returnUser.setName(user.getName());
//		returnUser.setGlobalRole(user.getGlobalRole());
//		returnUser.setUnencryptedPassword(user.getUnencryptedPassword());
//		returnUser.setPasswordConfirm(user.getPasswordConfirm());
//		returnUser.setHasGlobalGroupAccess(user.getHasGlobalGroupAccess());
//		returnUser.setIsLdapUser(user.getIsLdapUser());
		
		user.setAccessControlTeamMaps(returnUser.getAccessControlTeamMaps());
		user.setActive(returnUser.isActive());
		user.setApproved(returnUser.isApproved());
		user.setCreatedDate(returnUser.getCreatedDate());
		user.setCurrentPassword(returnUser.getCurrentPassword());
		user.setFailedPasswordAttempts(returnUser.getFailedPasswordAttempts());
		user.setFailedPasswordAttemptWindowStart(returnUser.getFailedPasswordAttemptWindowStart());
		user.setHasChangedInitialPassword(returnUser.isHasChangedInitialPassword());
		user.setId(userId);
		user.setLastLoginDate(returnUser.getLastLoginDate());
		user.setLastPasswordChangedDate(returnUser.getLastPasswordChangedDate());
		user.setModifiedDate(returnUser.getModifiedDate());
		user.setSalt(returnUser.getSalt());
		user.setPassword(returnUser.getPassword());
		user.setWasLdapUser(returnUser.getIsLdapUser());
		user.setUserEventNotificationMaps(returnUser.getUserEventNotificationMaps());
		user.setUserEventNotificationMapsInitialized(returnUser.getUserEventNotificationMapsInitialized());

		return user;
	}

	@Override
	public List<User> getPermissibleUsers(Integer orgId, Integer appId) {	
		List<User> resultList = null;
		if (orgId != null && appId == null) resultList = userDao.retrieveOrgPermissibleUsers(orgId);			
		if (appId != null && orgId != null) resultList = userDao.retrieveAppPermissibleUsers(orgId, appId);			
		return resultList;
	}

	@Override
	public void setRoleCommunity(User user) {

		if (!EnterpriseTest.isEnterprise()) {
			Role administrator = roleDao.retrieveByName("Administrator");
			if (administrator == null) {
				log.error("Administrator role not found in community version. Check your database");
			} else {
				user.setGlobalRole(administrator);
				user.setHasGlobalGroupAccess(true);
			}
		}
	}

	@Override
	public List<User> retrievePage(int page, int numberToShow) {
		return userDao.retrievePage(page, numberToShow);
	}

	@Override
	@Transactional(readOnly = true)
	public Long countUsers(String searchString) {
		return userDao.countUsers(searchString);
	}

	@Override
	@Transactional(readOnly = true)
	public Long countUsers() {
		return userDao.countUsers();
	}

	@Override
	public List<User> search(String searchString, int numResults, int page) {
		return userDao.getSearchResults(searchString, numResults, page);
	}

	@Override
	public List<User> search(HttpServletRequest request) {


		String searchString = request.getParameter("searchString");
		if (searchString == null) {
			searchString = "";
		}
		Long count = countUsers(searchString);

		Integer page = getIntegerOrNull(request.getParameter("page")),
				number = getIntegerOrNull(request.getParameter("number"));

		if (page == null || page < 1) {
			page = 1;
		}

		if (number == null || number < 1) {
			number = 1;
		}

		if ((page - 1) * number > count) {
			page = 1;
		}

		return search(searchString, number, page);
	}

	@Override
	public List<User> getUsersForRoleId(Integer id) {

		return userDao.loadUsersForRole(id);
	}

	@Override
	public Set<EventAction> getNotificationEventActions(User user) {
		if (!user.getUserEventNotificationMapsInitialized()) {
			initializeUserEventNotificationMaps(user);
			storeUser(user);
		}
		List<UserEventNotificationMap> userEventNotificationMaps = userEventNotificationMapDao.loadUserEventNotificationMaps(user);
		Set<EventAction> notificationEventActions = EnumSet.noneOf(EventAction.class);
		for (UserEventNotificationMap userEventNotificationMap : userEventNotificationMaps) {
			notificationEventActions.add(userEventNotificationMap.getEventActionEnum());
		}
		return notificationEventActions;
	}

	@Override
	public void setNotificationEventActions(User user, Set<EventAction> notificationEventActions) {
		Set<EventAction> currentNotificationEventActions = EnumSet.noneOf(EventAction.class);

		if (!user.isNew()) {
			List<UserEventNotificationMap> userEventNotificationMapsToRemove = list();

			List<UserEventNotificationMap> userEventNotificationMaps =
					userEventNotificationMapDao.loadUserEventNotificationMaps(user);
			for (UserEventNotificationMap userEventNotificationMap : userEventNotificationMaps) {
				if (!notificationEventActions.contains(userEventNotificationMap.getEventActionEnum())) {
					userEventNotificationMapsToRemove.add(userEventNotificationMap);
				} else {
					currentNotificationEventActions.add(userEventNotificationMap.getEventActionEnum());
				}
			}

			for (UserEventNotificationMap userEventNotificationMap : userEventNotificationMapsToRemove) {
				userEventNotificationMap.setUser(null);
				userEventNotificationMapDao.delete(userEventNotificationMap);
			}
		}

		for (EventAction eventAction : notificationEventActions) {
			if (!currentNotificationEventActions.contains(eventAction)) {
				UserEventNotificationMap userEventNotificationMap = new UserEventNotificationMap();
				userEventNotificationMap.setUser(user);
				userEventNotificationMap.setEventAction(eventAction.name());
				userEventNotificationMap.setActive(true);
				userEventNotificationMapDao.saveOrUpdate(userEventNotificationMap);
			}
		}
	}

	@Override
	public Map<Integer, Map<String, Boolean>> getUserEventNotificationSettings(List<User> users) {
		Map<Integer, Map<String, Boolean>> userEventNotificationSettings = new HashMap<>();
		for (User user : users) {
			Map<String, Boolean> eventNotificationSettings = new HashMap<>();
			userEventNotificationSettings.put(user.getId(), eventNotificationSettings);

			Set<EventAction> notificationEventActions = getNotificationEventActions(user);
			for (EventAction eventNotificationType : EventAction.values()) {
				if (notificationEventActions.contains(eventNotificationType)) {
					eventNotificationSettings.put(eventNotificationType.name(), true);
				} else {
					eventNotificationSettings.put(eventNotificationType.name(), false);
				}
			}
		}
		return userEventNotificationSettings;
	}
}
