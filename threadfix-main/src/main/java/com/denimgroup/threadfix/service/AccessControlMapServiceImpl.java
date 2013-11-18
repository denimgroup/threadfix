package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.AccessControlMapDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.webapp.viewmodels.AccessControlMapModel;

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
			
			if (map.getUser().getId() != null &&
					accessControlMapDao.retrieveTeamMapByUserTeamAndRole(
							map.getUser().getId(), org.getId(), role.getId()) != null) {
				return "That team / role combo already exists for this user.";
			}
		} else {
			map.setRole(null);
			
			if (map.getAccessControlApplicationMaps() == null || 
					map.getAccessControlApplicationMaps().size() == 0) {
				return "You must select at least one application.";
			}
			List<AccessControlApplicationMap> maps = new ArrayList<>();
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
				
				if (map.getUser().getId() != null) {
					AccessControlApplicationMap duplicateMap = accessControlMapDao.retrieveAppMapByUserAppAndRole(
							map.getUser().getId(), appMap.getApplication().getId(), role.getId());
					if (duplicateMap != null && (mapId == null ||
							!duplicateMap.getAccessControlTeamMap().getId().equals(mapId))) {
						return "You have a duplicate application / role entry for this user.";
					}
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
	public AccessControlTeamMap parseAccessControlTeamMap(
			AccessControlMapModel map) {
		if (map == null || map.getTeamId() == null) {
			return null;
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
		
		returnMap.setAllApps(map.isAllApps());
		
		if (map.getRoleId() != null && map.getRoleId() > 0) {
			returnMap.setRole(new Role());
			returnMap.getRole().setId(map.getRoleId());
		}
		
		Map<Integer, Integer> intMap = null;
		
		if (map.getRoleIdMapList() != null && map.getRoleIdMapList().size() > 0) {
			intMap = getMap(map.getRoleIdMapList());
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
		
		// TODO Auto-generated method stub
		return returnMap;
	}

	@Override
	public AccessControlTeamMap loadAccessControlTeamMap(Integer id) {
		return accessControlMapDao.retrieveTeamMapById(id);
	}

	private Map<Integer,Integer> getMap(List<String> stringMaps) {
		if (stringMaps == null || stringMaps.size() <= 0) {
			return null;
		}
		
		Map<Integer,Integer> intMap = new HashMap<>();
		
		for (String stringMap : stringMaps) {
			String[] matches = stringMap.split("-");
			if (matches != null && matches.length == 2) {
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
		
		return intMap;
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
		
		List<AccessControlTeamMap> mapsToRemove = new ArrayList<>();
		
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
			
			store(map);
		}
	}

}
