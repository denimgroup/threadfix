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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class LoginPageIT extends BaseIT {

	@Test
	public void testFieldsPresent(){
		assertTrue("Username field was not present on the page",loginPage.isUserNameFieldPresent());
        assertTrue("Password field was not present on the page",loginPage.isPasswordFieldPresent());
        assertTrue("Login button was not present on the page",loginPage.isLoginButtonPresent());
        assertTrue("Login button is not clickable",loginPage.isLoginButtonClickable());
	}
	
	@Test
	public void testFieldInputs(){
		String text = getName();
		
		loginPage = loginPage.setUsername(text);
		assertTrue("Username does not accept text properly",loginPage.getUserNameInput().equals(text));

        loginPage.setPassword(text);
        assertTrue("password does not accept text properly",loginPage.getLoginInput().equals(text));
	}
}
