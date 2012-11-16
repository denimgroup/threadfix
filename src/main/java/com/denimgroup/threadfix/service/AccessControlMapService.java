package com.denimgroup.threadfix.service;

import java.util.List;

import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import com.denimgroup.threadfix.webapp.viewmodels.AccessControlMapModel;

public interface AccessControlMapService {

	/**
	 * Parse the view model into the ThreadFix object. We may want to collapse 
	 * this so that we just use the Entity but that would make the child app / role
	 * relationship tricky.
	 * @param map
	 * @return
	 */
	AccessControlTeamMap parseAccessControlTeamMap(AccessControlMapModel map);
	
	/**
	 * Load the map with the given ID.
	 * @param id
	 * @return
	 */
	AccessControlTeamMap loadAccessControlTeamMap(Integer id);
	
	/**
	 * 
	 * @param mapId
	 * @return
	 */
	AccessControlApplicationMap loadAccessControlApplicationMap(int mapId);
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	List<AccessControlTeamMap> loadAllMapsForUser(Integer id);
	
	/**
	 * 
	 * @param map
	 */
	void store(AccessControlTeamMap map);
	
	/**
	 * 
	 * @param map
	 */
	void store(AccessControlApplicationMap map);

	/**
	 * This method needs to make sure that the map is valid,
	 * actually gives the user a role on an app or team, and
	 * doesn't have invalid IDs or apps that don't correspond to the 
	 * submitted team. 
	 * 
	 * @param map
	 * @return
	 */
	String validateMap(AccessControlTeamMap map, Integer mapId);

	/**
	 * 
	 * @param map
	 */
	void deactivate(AccessControlApplicationMap map);

	/**
	 * 
	 * @param map
	 */
	void deactivate(AccessControlTeamMap map);

}
