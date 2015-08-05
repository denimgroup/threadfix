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

import com.denimgroup.threadfix.data.dao.APIKeyDao;
import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.List;

@Service
@Transactional(readOnly = false) // used to be true
public class APIKeyServiceImpl implements APIKeyService {
	
	protected final SanitizedLogger log = new SanitizedLogger(APIKeyService.class);

	private APIKeyDao apiKeyDao = null;

	@Autowired
	public APIKeyServiceImpl(APIKeyDao apiKeyDao) {
		this.apiKeyDao = apiKeyDao;
	}

	@Override
	public List<APIKey> loadAll() {
		return apiKeyDao.retrieveAllActive();
	}

	@Override
	public APIKey loadAPIKey(int apiKeyId) {
		return apiKeyDao.retrieveById(apiKeyId);
	}
	
	@Override
	public APIKey loadAPIKey(String key) {		
		return apiKeyDao.retrieveByKey(key);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeAPIKey(APIKey apiKey) {
		apiKeyDao.saveOrUpdate(apiKey);
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateApiKey(APIKey apiKey) {
		log.info("Deleting API Key with id " + apiKey.getId());

		apiKey.setUser(null);
		apiKey.setActive(false);
		apiKeyDao.saveOrUpdate(apiKey);
	}

	@Override
	public APIKey createAPIKey(String note, boolean restricted) {
		APIKey key = new APIKey();
		
		String editedNote = note;
		
		if (editedNote != null && editedNote.length() > 255)
			editedNote = editedNote.substring(0, 254);
		
		String keyString = generateNewSecureRandomKey();
		
		if (keyString != null && keyString.length() > 50)
			keyString = keyString.substring(0, 49);
		
		key.setNote(editedNote);
		key.setIsRestrictedKey(restricted);
		key.setApiKey(keyString);
		
		return key;
	}
	
	public String generateNewSecureRandomKey() {
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

			String newKey = "";
			
			newKey = newKey.concat(DatatypeConverter.printBase64Binary(toByteArray(random.nextLong())).trim());
			newKey = newKey.concat(DatatypeConverter.printBase64Binary(toByteArray(random.nextLong())).trim());
			newKey = newKey.concat(DatatypeConverter.printBase64Binary(toByteArray(random.nextLong())).trim());
			newKey = newKey.concat(DatatypeConverter.printBase64Binary(toByteArray(random.nextLong())).trim());
						
			newKey = newKey.replaceAll("[\\[!@#$%\\^&*\\(\\)=\\-+/]", "");
			
			return newKey;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			log.error("Encountered error while generating API Key.", e);
		}
		
		log.error("API Key Generation failed. Make sure the algorithm is supported.");
		return null;
	}
	
	private byte[] toByteArray(long data) {
		return new byte[] {
				(byte)((data >> 56) & 0xff),
				(byte)((data >> 48) & 0xff),
				(byte)((data >> 40) & 0xff),
				(byte)((data >> 32) & 0xff),
				(byte)((data >> 24) & 0xff),
				(byte)((data >> 16) & 0xff),
				(byte)((data >> 8) & 0xff),
				(byte)((data >> 0) & 0xff),
		};
	}
}
