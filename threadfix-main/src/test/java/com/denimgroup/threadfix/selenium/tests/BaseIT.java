////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.junit.After;
import org.junit.Before;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;


public abstract class BaseIT {
	protected WebDriver driver;
    protected LoginPage loginPage;

    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");

    static {
        if (API_KEY == null) {
            throw new RuntimeException("Please set API_KEY in run configuration.");
        }

        if (REST_URL == null) {
            throw new RuntimeException("Please set REST_URL in run configuration.");
        }
    }

	public BaseIT() {
		DesiredCapabilities capability = new DesiredCapabilities();
        capability.setBrowserName(DesiredCapabilities.firefox().getBrowserName());
        FirefoxProfile profile = new FirefoxProfile();
        capability.setCapability(FirefoxDriver.PROFILE, profile);
        capability.setCapability(CapabilityType.ACCEPT_SSL_CERTS, true);

        profile.setAcceptUntrustedCertificates(true);

        driver = new FirefoxDriver(capability);
	}

	@Before
	public void init() {
        loginPage = LoginPage.open(driver);
    }

	@After
	public void shutDown() {
        driver.quit();
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * This method is a wrapper for RandomStringUtils.random with a preset character set.
	 * @return random string
	 */
	protected String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}

    protected String getName() {
        return getRandomString(12);
    }

    /**
     * This method will create a team in the ThreadFix DBS
     * @return String of the team's name that has just been created in ThreadFix
     */
    protected String createTeam() {
        String teamName = getName();
        DatabaseUtils.createTeam(teamName);
        return teamName;
    }

    /**
     * This method will create an application in the ThreadFix DBS
     * @param teamName non-null, and valid team name must be provided
     * @return String of the application's name that has just been created in ThreadFix
     */
    protected String createApplication(String teamName) {
        if (teamName != null) {
            String appName = getName();
            DatabaseUtils.createApplication(teamName, appName);
            return appName;
        } else
            throw new RuntimeException("An application must be created within a team.");
    }

    /**
     * This method will create a regular user with no role in the ThreadFix DBS
     * @return String of the user's name that was just created in ThreadFix
     */
    protected String createRegularUser() {
        String userName = getName();
        DatabaseUtils.createUser(userName);
        return userName;
    }

    /**
     * This method will create an admin user with no role in the ThreadFix DBS
     * @return String of the user's name that was just created in ThreadFix
     */
    protected String createAdminUser() {
        String userName = getName();
        DatabaseUtils.createUser(userName, "Administrator");
        return userName;
    }

    /**
     * This method will create a user with the specific role that is passed as a parameter
     * @param role non-null, and a valid role name must be provided
     * @return String of the user's name that was just created in ThreadFix
     */
    protected String createSpecificRoleUser(String role) {
        if (role != null) {
            String userName = getName();
            DatabaseUtils.createUser(userName, role);
            return userName;
        } else
            throw new RuntimeException("A valid specific role must given to the user.");
    }

    /**
     * This method will create a role with all permissions granted
     * @return String of the role's name that was just created in ThreadFix
     */
    protected String createRole() {
        String roleName = getName();
        DatabaseUtils.createRole(roleName, true);
        return roleName;
    }

    protected String createTag() {
        String tagName = getName();
        DatabaseUtils.createTag(tagName);
        return tagName;
    }


}
