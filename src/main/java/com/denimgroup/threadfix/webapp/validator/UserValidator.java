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
package com.denimgroup.threadfix.webapp.validator;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import com.denimgroup.threadfix.data.entities.User;

public class UserValidator implements Validator {

	@Override
	public boolean supports(@SuppressWarnings("rawtypes") Class clazz) {
		return User.class.equals(clazz);
	}

	@Override
	public void validate(Object target, Errors errors) {
		User user = (User) target;
		
		if (!user.getHasGlobalGroupAccess() || user.getGlobalRole() == null ||
				user.getGlobalRole().getId() == null || user.getGlobalRole().getId() == null ||
				user.getGlobalRole().getId() == 0) {
			user.setGlobalRole(null);
		}

		if (isEmptyOrWhitespace(user.getName()))
			errors.rejectValue("name", "errors.required", new String[] { "Name" }, null);
		else if (user.getName() != null && user.getName().length() > 25) {
			errors.rejectValue("name", null, "Name has a maximum length of 25.");
		}

		// Validate password
		if (!user.getIsLdapUser()) {
			if (user.isNew()) {
				if (isEmptyOrWhitespace(user.getUnencryptedPassword())) {
					errors.rejectValue("password", "errors.required", new String[] { "Password" }, "");
				}
			}
	
			if (errors.getFieldError("password") == null && user.getUnencryptedPassword() != null && 
					user.getUnencryptedPassword().length() < 12 &&
					user.getUnencryptedPassword().length() != 0) {
				errors.rejectValue("password", null, "Password has a minimum length of 12.");
			}
	
			// Confirm password
			if (errors.getFieldError("password") == null) {
				if (!isEmptyOrWhitespace(user.getUnencryptedPassword())
						|| !isEmptyOrWhitespace(user.getPasswordConfirm())) {
					if (isEmptyOrWhitespace(user.getUnencryptedPassword())) {
						errors.rejectValue("password", null, "Passwords do not match.");
					} else if (isEmptyOrWhitespace(user.getPasswordConfirm())) {
						errors.rejectValue("password", null, "Passwords do not match.");
					} else if (!user.getUnencryptedPassword().equals(user.getPasswordConfirm())) {
						errors.rejectValue("password", null, "Passwords do not match.");
					}
				}
			}
		}
	}

	private boolean isEmptyOrWhitespace(String value) {
		return (value == null) || (value.trim().equals(""));
	}
}
