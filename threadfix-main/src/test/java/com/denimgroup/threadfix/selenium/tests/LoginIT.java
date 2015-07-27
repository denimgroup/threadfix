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

package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class LoginIT extends BaseIT {

	@Test
	public void testBadUsername(){
		loginPage = loginPage.loginInvalid("WRONG!!!","password");
		assertTrue("Invalid login username error message was incorrect",loginPage.isLoginErrorPresent());
	}
	
	@Test
	public void testBadPassword(){
		//wrong password
		loginPage = loginPage.loginInvalid("user","WRONG!!!");
		assertTrue("Invalid login password error message was incorrect",loginPage.isLoginErrorPresent());
		//case check
		loginPage = loginPage.loginInvalid("user","PASSWORD");
		assertTrue("Invalid login password error message was incorrect",loginPage.isLoginErrorPresent());
		//white space
		loginPage = loginPage.loginInvalid("user","p a s s w o r d");
		assertTrue("Invalid login password error message was incorrect",loginPage.isLoginErrorPresent());
		loginPage = loginPage.loginInvalid("user"," password ");
		assertTrue("Invalid login password error message was incorrect",loginPage.isLoginErrorPresent());
	}
	
	@Test
	public void testValidLoginLogout(){
		DashboardPage dashboardPage = loginPage.defaultLogin();
		assertTrue("Correct user was not logged in",dashboardPage.isLoggedInUser("user"));
		loginPage = dashboardPage.logout();
		assertTrue("User was not logged out",loginPage.isLoggedOut());
		
	}
	
}
