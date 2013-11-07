////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;

public interface RemoteProviderApplicationService {
	/**
	 * 
	 * @param id
	 * @return
	 */
	RemoteProviderApplication load(int id);
	
	/**
	 * 
	 * @param remoteProviderApplication
	 */
	void store(RemoteProviderApplication remoteProviderApplication);
	
	/**
	 * 
	 * @param remoteProviderType
	 */
	void updateApplications(RemoteProviderType remoteProviderType);
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	List<RemoteProviderApplication> loadAllWithTypeId(int id);
	
	/**
	 * 
	 * @param remoteProviderType
	 * @return
	 */
	List<RemoteProviderApplication> getApplications(RemoteProviderType remoteProviderType);
	
	/**
	 * 
	 * @param remoteProviderType
	 */
	void deleteApps(RemoteProviderType remoteProviderType);

	/**
	 * 
	 * @param result
	 * @param remoteProviderApplication
	 * @param application
	 */
	String processApp(BindingResult result, RemoteProviderApplication remoteProviderApplication, Application application);

	/**
	 * 
	 * @return
	 */
	List<RemoteProviderApplication> loadAllWithMappings();
	

	/**
	 * 
	 */
	void addBulkImportToQueue(RemoteProviderType remoteProviderType);

	/**
	 * 
	 * @param result
	 * @param remoteProviderApplication
	 * @param appId
	 * @return
	 */
	String deleteMapping(BindingResult result,
			RemoteProviderApplication remoteProviderApplication,
			int appId);
}
