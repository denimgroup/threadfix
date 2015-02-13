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

import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

// TODO This needs to be updated, but more research is needed to determine impact on existing systems
// we can't make updates that make it impossible to use existing credentials
@Service
public class ThreadFixPasswordEncoder implements PasswordEncoder {

	@Override
	public String encodePassword(String rawPass, Object salt) throws DataAccessException {
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

		return encPass.equals(encodePassword(rawPass, salt));
	}

	/**
	 * @param bytes
	 * @return
	 */
	public String convertBytesToHexString(byte[] bytes) {
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
	public String generateSalt() {
		java.util.UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}

	/**
	 * @param password
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public String generatePasswordHash(String password, String salt)
			throws NoSuchAlgorithmException {
		String newPassword = password + salt;
		MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
		msgDigest.update(newPassword.getBytes());
		String pwHash = convertBytesToHexString(msgDigest.digest());

		return pwHash;
	}

}
