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

import com.denimgroup.threadfix.data.Option;
import com.denimgroup.threadfix.data.dao.AccessControlMapDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.beans.AccessControlMapModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
public class AccessControlMapServiceImpl implements AccessControlMapService {
	
	protected final SanitizedLogger log = new SanitizedLogger(ApplicationServiceImpl.class);
	
	private AccessControlMapDao accessControlMapDao;
	private RoleDao roleDao;
	private OrganizationDao organizationDao;
	private ApplicationDao applicationDao;
	
	@Autowired
	public AccessControlMapServiceImpl(RoleDao roleDao,
			ApplicationDao applicationDao,
			OrganizationDao organizationDao,
			AccessControlMapDao accessControlMapDao) {
		this.accessControlMapDao = accessControlMapDao;
		this.roleDao = roleDao;
		this.applicationDao = applicationDao;
		this.organizationDao = organizationDao;
	}
	
	@Override
	public String validateMap(AccessControlTeamMap map, Integer mapId) {
		if (map == null) 
			return "Something went wrong.";
		
		if (map.getOrganization() == null || map.getOrganization().getId() == null) {
			return "You must pick a Team.";
		}
		Organization org = organizationDao.retrieveById(map.getOrganization().getId());
		if (org == null) {
			return "You must pick a Team.";
		}
		map.setOrganization(org);
		
		if (map.getAllApps()) {
			map.setAccessControlApplicationMaps(null);
			
			if (map.getRole() == null || map.getRole().getId() == null) {
				return "You must pick a Role.";
			}
			Role role = roleDao.retrieveById(map.getRole().getId());
			if (role == null) {
				return "You must pick a Role.";
			}
			map.setRole(role);
			
			if (map.getUser() != null && map.getUser().getId() != null &&
					accessControlMapDao.retrieveTeamMapByUserTeamAndRole(
							map.getUser().getId(), org.getId(), role.getId()) != null) {
				return "That team / role combination already exists for this user.";
			} else if (map.getGroup() != null && map.getGroup().getId() != null) {

				AccessControlTeamMap dbMap = accessControlMapDao.retrieveTeamMapByGroupTeamAndRole(
						map.getGroup().getId(), org.getId(), role.getId());
				if (dbMap != null && dbMap.getId().equals(mapId)) {
					return "That team / role combination already exists for this group.";
				}
			}
		} else {
			map.setRole(null);
			
			if (map.getAccessControlApplicationMaps() == null || 
					map.getAccessControlApplicationMaps().size() == 0) {
				return "You must set at least one role.";
			}
			List<AccessControlApplicationMap> maps = list();
			for (AccessControlApplicationMap appMap : map.getAccessControlApplicationMaps()) {
				if (appMap.getApplication() == null || appMap.getApplication().getId() == null) {
					maps.add(appMap);
					continue;
				}

				Application application = applicationDao.retrieveById(appMap.getApplication().getId());
				if (application == null || application.getOrganization() == null || 
						!application.getOrganization().getId().equals(org.getId())) {
					maps.add(appMap);
					continue;
				}
				appMap.setApplication(application);
				
				if (appMap.getRole() == null || appMap.getRole().getId() == null) {
					return "You must select a Role for each Application.";
				}
				Role role = roleDao.retrieveById(appMap.getRole().getId());
				if (role == null) {
					return "You must select a Role for each Application.";
				}
				appMap.setRole(role);
				
				if (map.getUser() != null && map.getUser().getId() != null) {
					AccessControlApplicationMap duplicateMap = accessControlMapDao.retrieveAppMapByUserAppAndRole(
							map.getUser().getId(), appMap.getApplication().getId(), role.getId());
					if (duplicateMap != null && (mapId == null ||
							!duplicateMap.getAccessControlTeamMap().getId().equals(mapId))) {
						return "You have a duplicate application / role entry for this user.";
					}

				} else if (map.getGroup() != null && map.getGroup().getId() != null) {
					AccessControlApplicationMap duplicateMap = accessControlMapDao.retrieveAppMapByGroupAppAndRole(
							map.getGroup().getId(), appMap.getApplication().getId(), role.getId());
					if (duplicateMap != null && (mapId == null ||
							!duplicateMap.getAccessControlTeamMap().getId().equals(mapId))) {
						return "You have a duplicate application / role entry for this group.";
					}
				} else {
					return "Neither User nor Group was found.";
				}
			}
			
			map.getAccessControlApplicationMaps().removeAll(maps);
			
			if (map.getAccessControlApplicationMaps().size() == 0) {
				return "You must select at least one application.";
			}
		}
		
		return null;
	}

	@Override
	public Option<AccessControlTeamMap> parseAccessControlTeamMap(
            AccessControlMapModel map) {
		if (map == null || map.getTeamId() == null) {
            assert false : "This indicates a coding error or parameter tampering.";
			return Option.failure();
		}
		
		AccessControlTeamMap returnMap = new AccessControlTeamMap();
		if (map.getTeamId() != null && map.getTeamId() > 0) {
			returnMap.setOrganization(new Organization());
			returnMap.getOrganization().setId(map.getTeamId());
		}

		if (map.getUserId() != null && map.getUserId() > 0) {
			returnMap.setUser(new User());
			returnMap.getUser().setId(map.getUserId());
		}

		if (map.getGroupId() != null && map.getGroupId() > 0) {
			returnMap.setGroup(new Group());
			returnMap.getGroup().setId(map.getGroupId());
		}
		
		returnMap.setAllApps(map.isAllApps());
		
		if (map.getRoleId() != null && map.getRoleId() > 0) {
			returnMap.setRole(new Role());
			returnMap.getRole().setId(map.getRoleId());
		}
		
		Map<Integer, Integer> intMap = null;
		
		if (map.getRoleIdMapList() != null && map.getRoleIdMapList().size() > 0) {
			Option<Map<Integer, Integer>> optionMap = getMap(map.getRoleIdMapList());

            if (optionMap.isValid()) {
                intMap = optionMap.getValue();
            }
		}
		
		if (!returnMap.getAllApps() && map.getApplicationIds() != null) {
			returnMap.setAccessControlApplicationMaps(new ArrayList<AccessControlApplicationMap>());
			for (Integer applicationId : map.getApplicationIds()) {
				AccessControlApplicationMap childMap = new AccessControlApplicationMap();
				childMap.setApplication(new Application());
				childMap.getApplication().setId(applicationId);
				if (intMap != null && intMap.get(applicationId) != null) {
					childMap.setRole(new Role());
					childMap.getRole().setId(intMap.get(applicationId));
				}
				childMap.setAccessControlTeamMap(returnMap);
				returnMap.getAccessControlApplicationMaps().add(childMap);
			}
		}

		if (returnMap.getUser() == null && returnMap.getGroup() == null) {
			return Option.failure();
		}
		
		return Option.success(returnMap);
	}

	@Override
	public AccessControlTeamMap loadAccessControlTeamMap(Integer id) {
		return accessControlMapDao.retrieveTeamMapById(id);
	}

	private Option<Map<Integer,Integer>> getMap(List<String> stringMaps) {
		if (stringMaps == null || stringMaps.size() <= 0) {
			return Option.failure();
		}
		
		Map<Integer,Integer> intMap = new HashMap<>();
		
		for (String stringMap : stringMaps) {
			String[] matches = stringMap.split("-");
			if (matches.length == 2) {
				try {
					if (matches[0].matches("^[0-9]+$") &&
							matches[1].matches("^[0-9]+$")) {
						intMap.put(Integer.valueOf(matches[0]), Integer.valueOf(matches[1]));
					}
				} catch (NumberFormatException e) {
					log.warn("Incorrect format passed into model from web interface. Integers could not be parsed.", e);
				}
			}
		}
		
		return Option.success(intMap);
	}
	
	@Override
	public AccessControlApplicationMap loadAccessControlApplicationMap(int mapId) {
		return accessControlMapDao.retrieveAppMapById(mapId);
	}

	@Transactional(readOnly=false)
	@Override
	public void store(AccessControlTeamMap map) {
		accessControlMapDao.saveOrUpdate(map);
	}

	@Transactional(readOnly=false)
	@Override
	public void store(AccessControlApplicationMap map) {
		accessControlMapDao.saveOrUpdate(map);
	}

	@Override
	public List<AccessControlTeamMap> loadAllMapsForUser(Integer id) {
		List<AccessControlTeamMap> maps = accessControlMapDao.retrieveAllMapsForUser(id);
		
		List<AccessControlTeamMap> mapsToRemove = list();
		
		outer: for (AccessControlTeamMap map : maps) {
			if (map.getAllApps()) {
				continue;
			}
			
			for (AccessControlApplicationMap appMap : map.getAccessControlApplicationMaps()) {
				if (appMap.isActive()) {
					continue outer;
				}
			}
			
			mapsToRemove.add(map);
		}
		maps.removeAll(mapsToRemove);
		
		return maps;
	}

	@Override
	@Transactional(readOnly=false)
	public void deactivate(AccessControlApplicationMap map) {
		if (map != null) {
			map.setActive(false);
			map.setModifiedDate(new Date());
			store(map);
		}
	}
	
	@Override
	@Transactional(readOnly=false)
	public void deactivate(AccessControlTeamMap map) {
		if (map != null) {
			map.setActive(false);
			map.setModifiedDate(new Date());
			
			if (map.getAccessControlApplicationMaps() != null) {
				for (AccessControlApplicationMap appMap : map.getAccessControlApplicationMaps()) {
					deactivate(appMap);
				}
			}

			map.setGroup(null);
			map.setUser(null);
			
			store(map);
		}
	}

}
