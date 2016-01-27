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

import com.denimgroup.threadfix.data.Option;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import com.denimgroup.threadfix.service.beans.AccessControlMapModel;

import java.util.List;

public interface AccessControlMapService {

	/**
	 * Parse the view model into the ThreadFix object. We may want to collapse 
	 * this so that we just use the Entity but that would make the child app / role
	 * relationship tricky.
	 * @param map
	 * @return
	 */
	Option<AccessControlTeamMap> parseAccessControlTeamMap(AccessControlMapModel map);
	
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
