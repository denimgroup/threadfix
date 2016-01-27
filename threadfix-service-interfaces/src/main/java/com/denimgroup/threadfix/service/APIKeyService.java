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

import java.util.List;

import com.denimgroup.threadfix.data.entities.APIKey;

/**
 * @author mcollins
 * 
 */
public interface APIKeyService {

	/**
	 * @return
	 */
	List<APIKey> loadAll();

	/**
	 * @param apiKeyId
	 * @return
	 */
	APIKey loadAPIKey(int apiKeyId);
	
	/**
	 * Load the API key from the database
	 * @param key
	 * @return
	 */
	APIKey loadAPIKey(String key);

	/**
	 * @param apiKey
	 */
	void storeAPIKey(APIKey apiKey);

	/**
	 * @param organizationId
	 */
	void deactivateApiKey(APIKey apiKey);

	/**
	 * Create a new securely random API Key and package it in the APIKey object with the note.
	 * @param note
	 * @return
	 */
	APIKey createAPIKey(String note, boolean restricted);
	
	/**
	 * 
	 * @return
	 */
	String generateNewSecureRandomKey();
	
}
