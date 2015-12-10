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

import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static com.denimgroup.threadfix.util.RawPropertiesHolder.getProperty;

// TODO This needs to be updated, but more research is needed to determine impact on existing systems
// we can't make updates that make it impossible to use existing credentials
@Service
public class ThreadFixPasswordEncoder implements PasswordEncoder {

	protected final SanitizedLogger log = new SanitizedLogger(ThreadFixPasswordEncoder.class);

	BCryptPasswordEncoder bCryptPasswordEncoder = null;

	public ThreadFixPasswordEncoder() {
		Integer bCryptStrength = getBCryptStrength();
		if (bCryptStrength != null) {
			bCryptPasswordEncoder = new BCryptPasswordEncoder(bCryptStrength);
		} else {
			bCryptPasswordEncoder = new BCryptPasswordEncoder();
		}
	}

	private Integer getBCryptStrength() {
		String bCryptStrengthString = getProperty("bcrypt.strength");
		Integer bCryptStrength = IntegerUtils.getIntegerOrNull(bCryptStrengthString);
		if (bCryptStrength == null) {
			log.warn("bcrypt.strength property is not a valid integer from 4 to 31 and will be ignored");
		}
		return bCryptStrength;
	}

	@Override
	public String encodePassword(String rawPass, Object salt) throws DataAccessException {
		return bCryptPasswordEncoder.encode(rawPass);
	}

	private String legacyEncodePassword(String rawPass, Object salt) throws DataAccessException {
		String encodedPass = null;

		try {
			if (salt == null) {
				encodedPass = generatePasswordHash(rawPass, generateSalt());
			} else {
				encodedPass = generatePasswordHash(rawPass, (String) salt);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return encodedPass;
	}

	@Override
	public boolean isPasswordValid(String encPass, String rawPass, Object salt)
			throws DataAccessException {
		if ((salt != null) && !salt.toString().trim().equals("")) {
			return encPass.equals(legacyEncodePassword(rawPass, salt));
		} else {
			return bCryptPasswordEncoder.matches(rawPass, encPass);
		}
	}

	/**
	 * @param bytes
	 * @return
	 */
	private String convertBytesToHexString(byte[] bytes) {
		StringBuffer hexString = new StringBuffer();

		for (int i = 0; i < bytes.length; i++) {
			String temp = Integer.toHexString(0xFF & bytes[i]);
			if (temp.length() == 1) {
				hexString.append('0');
			}
			hexString.append(temp);
		}

		return hexString.toString();
	}

	/**
	 * @return
	 */
	private String generateSalt() {
		java.util.UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}

	/**
	 * @param password
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String generatePasswordHash(String password, String salt)
			throws NoSuchAlgorithmException {
		String newPassword = password + salt;
		MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
		msgDigest.update(newPassword.getBytes());
		String pwHash = convertBytesToHexString(msgDigest.digest());

		return pwHash;
	}

	public boolean isPasswordLegacyEncoded(User user) {
		if ((user.getSalt() != null) && !user.getSalt().trim().equals("")) {
			return true;
		}
		return false;
	}

	public boolean isPasswordEncodingStrengthBelowConfiguration(User user) {
		String encodedPassword = user.getPassword();
		if ((encodedPassword.length() > 7) && (encodedPassword.startsWith("$2a$"))) {
			String encodedBCryptStrengthString = encodedPassword.substring(4, 6);
			Integer encodedBCryptStrength = IntegerUtils.getIntegerOrNull(encodedBCryptStrengthString);
			Integer configurationBCryptStrength = getBCryptStrength();
			if ((encodedBCryptStrength != null)
					&& (configurationBCryptStrength != null)
					&& encodedBCryptStrength >= configurationBCryptStrength) {
				return false;
			}
		}
		return true;
	}

}
