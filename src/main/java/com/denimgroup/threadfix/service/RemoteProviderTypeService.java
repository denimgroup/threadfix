////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.RemoteProviderType;

public interface RemoteProviderTypeService {
	
	String USE_OLD_PASSWORD = "no password here.";
	String API_KEY_PREFIX = "************************";

	/**
	 * 
	 * @return
	 */
	List<RemoteProviderType> loadAll();
	
	/**
	 * 
	 * @param name
	 * @return
	 */
	RemoteProviderType load(String name);
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	RemoteProviderType load(int id);
	
	/**
	 * 
	 * @param remoteProviderType
	 */
	void store(RemoteProviderType remoteProviderType);
	
	/**
	 * Checks over the remote configuration and puts any errors into the result.
	 * This is to tidy up the controller layer.
	 * @param remoteProviderType
	 * @param result
	 */
	void checkConfiguration(RemoteProviderType remoteProviderType, 
			BindingResult result, int typeId);
	
	/**
	 * Deletes all apps and username / password / API key
	 * @param id
	 * @return
	 */
	void clearConfiguration(int id);

	/**
	 * 
	 * @param type
	 * @return
	 */
	RemoteProviderType decryptCredentials(RemoteProviderType type);
	
}
