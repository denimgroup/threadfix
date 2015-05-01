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

package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;

import java.util.List;

public interface AccessControlMapDao {

	/**
	 * @param id
	 * @return
	 */
	AccessControlTeamMap retrieveTeamMapById(int id);
	
	/**
	 * @param id
	 * @return
	 */
	AccessControlApplicationMap retrieveAppMapById(int id);
	
	/**
	 * 
	 * @param organizationId
	 * @param roleId
	 * @return
	 */
	AccessControlTeamMap retrieveTeamMapByUserTeamAndRole(int userId, int organizationId, int roleId);

	/**
	 * 
	 * @param applicationId
	 * @param roleId
	 * @return
	 */
	AccessControlApplicationMap retrieveAppMapByUserAppAndRole(int userId, int applicationId, int roleId);
	
	/**
	 * @param id
	 * @return
	 */
	List<AccessControlTeamMap> retrieveAllMapsForUser(Integer id);

	void saveOrUpdate(AccessControlTeamMap map);
	
	void saveOrUpdate(AccessControlApplicationMap map);

	AccessControlTeamMap retrieveTeamMapByGroupTeamAndRole(int groupId,
														   int organizationId, int roleId);

	AccessControlApplicationMap retrieveAppMapByGroupAppAndRole(int groupId,
																int applicationId, int roleId);
}
