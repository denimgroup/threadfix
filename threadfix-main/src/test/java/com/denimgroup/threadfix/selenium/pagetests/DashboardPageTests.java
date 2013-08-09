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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
//import org.openqa.selenium.remote.RemoteWebDriver;


import com.denimgroup.threadfix.selenium.pages.DashboardPage;
//import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DashboardPageTests extends PageBaseTest {

	public DashboardPageTests(String browser) {
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
	
	@After
	public void shutdown(){
		super.shutDown();
	}
	
	@Test
	public void monthBurndownGraphPresentTest(){
		assertTrue("6 month burndown graph section is not present",dashboardPage.is6MonthGraphPresent());
	}
	
	@Test
	public void top10GraphPresentTest(){
		assertTrue("Top 10 graph section is not present",dashboardPage.isTop10GraphPresent());
	}
}
