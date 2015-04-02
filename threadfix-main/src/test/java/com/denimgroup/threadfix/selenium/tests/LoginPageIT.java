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

    //TODO: Consolidate these tests.
	@Test
	public void testUsernameFieldPresent(){
		assertTrue("Username field was not present on the page",loginPage.isUserNameFieldPresent());
	}
	
	@Test
	public void testUsernameFieldInput(){
		String username = getName();
		
		loginPage = loginPage.setUsername(username);
		
		assertTrue("Username does not accept text properly",loginPage.getUserNameInput().equals(username));
	}
	
	@Test
	public void testPasswordFieldPresent(){
		assertTrue("Password field was not present on the page",loginPage.isPasswordFieldPresent());
	}
	
	@Test
	public void testPasswordFieldInput(){
		String password = getName();
		
		loginPage = loginPage.setPassword(password);
		
		assertTrue("password does not accept text properly",loginPage.getLoginInput().equals(password));
	}
	
	@Test
	public void testLoginButtonPresent(){
		assertTrue("Login button was not present on the page",loginPage.isLoginButtonPresent());
	}
	
	@Test
	public void testLoginButtonClickable(){
		assertTrue("Login button is not clickable",loginPage.isLoginButtonClickable());
	}
	
}
