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

import java.util.List;

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;

public interface RemoteProviderApplicationService {
	/**
	 * 
	 * @param id
	 * @return
	 */
	public RemoteProviderApplication load(int id);
	
	/**
	 * 
	 * @param remoteProviderApplication
	 */
	public void store(RemoteProviderApplication remoteProviderApplication);
	
	/**
	 * 
	 * @param remoteProviderType
	 */
	public void updateApplications(RemoteProviderType remoteProviderType);
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	public List<RemoteProviderApplication> loadAllWithTypeId(int id);
	
	/**
	 * 
	 * @param remoteProviderType
	 * @return
	 */
	public List<RemoteProviderApplication> getApplications(RemoteProviderType remoteProviderType);
	
	/**
	 * 
	 * @param remoteProviderType
	 */
	public void deleteApps(RemoteProviderType remoteProviderType);

	/**
	 * 
	 * @param appId
	 */
	public void importScanForApplication(RemoteProviderApplication remoteProviderApplication);
}
