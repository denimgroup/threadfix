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
package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;

public class HeaderPageTest extends PageBaseTest {
	public HeaderPageTest(String browser) {
		super(browser);
	}

//	private static LoginPage loginPage;
//	private RemoteWebDriver driver;
	private DashboardPage dashboardPage;
	
	@Before
	public void init() {
		super.init();
//		driver = (RemoteWebDriver) super.getDriver();
		dashboardPage = login();
	}
	
	@Test
	public void dashboardHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isDashboardMenuLinkPresent());
	}
	
	@Test
	public void applicationsHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isApplicationMenuLinkPresent());
	}
	
	@Test
	public void scansHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isScansMenuLinkPresent());
	}
	
	@Test
	public void reportsHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isReportsMenuLinkPresent());
	}
	
	@Test
	public void userHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isUsersMenuLinkPresent());
	}
	
	@Test
	public void configHeaderElementPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isConfigMenuLinkPresent());
	}
	
	@Test
	public void logoIsPresentTest(){
		assertTrue("Dashboard header link is not present",dashboardPage.isLogoPresent());
	}
	
}
