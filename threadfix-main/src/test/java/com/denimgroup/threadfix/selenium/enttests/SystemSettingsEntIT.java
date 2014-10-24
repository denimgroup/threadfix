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
package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.SystemSettingsPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class SystemSettingsEntIT extends BaseIT{
    private SystemSettingsPage systemSettingsPage;

    private static final String LDAP_SEARCHBASE = System.getProperty("LDAP_SEARCHBASE");
    private static final String LDAP_USERDN = System.getProperty("LDAP_USERDN");
    private static final String LDAP_PASSWORD = System.getProperty("LDAP_PASSWORD");
    private static final String LDAP_URL = System.getProperty("LDAP_URL");
    private static final String LDAP_USERNAME = System.getProperty("LDAP_USERNAME");
    private static final String LDAP_USERPASSWORD = System.getProperty("LDAP_USERPASSWORD");

    static {
        if (LDAP_SEARCHBASE == null) {
            throw new RuntimeException("Please set LDAP_SEARCHBASE in run configuration.");
        }
        if (LDAP_USERDN == null) {
            throw new RuntimeException("Please set LDAP_USERDN in run configuration.");
        }
        if (LDAP_PASSWORD == null) {
            throw new RuntimeException("Please set LDAP_PASSWORD in run configuration.");
        }
        if (LDAP_URL == null) {
            throw new RuntimeException("Please set LDAP_URL in run configuration.");
        }
        if (LDAP_USERNAME == null) {
            throw new RuntimeException("Please set LDAP_USERNAME in run configuration.");
        }
        if (LDAP_USERPASSWORD == null) {
            throw new RuntimeException("Please set LDAP_USERPASSWORD in run configuration.");
        }
    }

    @Before
    public void initialNavigation() {
        systemSettingsPage = loginPage.defaultLogin()
                .clickSystemSettingsLink();
    }

    @Test
    public void testValidLDAPSettings() {
        String invalidUserPassword = getRandomString(15);

        systemSettingsPage.expandLDAPSettings()
                .setLDAPSearchBase(LDAP_SEARCHBASE)
                .setLDAPUserDN(LDAP_USERDN)
                .setLDAPPassword(LDAP_PASSWORD)
                .setLDAPUrl(LDAP_URL)
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        DashboardPage dashboardPage = systemSettingsPage.logout()
                .login(LDAP_USERNAME, LDAP_USERPASSWORD);

        assertTrue("Valid LDAP user was unable to login using valid LDAP settings.", dashboardPage.isLoggedin());

        loginPage = dashboardPage.logout()
                .loginInvalid(LDAP_USERNAME, invalidUserPassword);

        assertTrue("Invalid LDAP user was not able to log in.", loginPage.isLoginErrorPresent());
    }

    @Test
    public void testInvalidLDAPSettings() {
        systemSettingsPage.expandLDAPSettings()
                .setLDAPSearchBase(LDAP_SEARCHBASE)
                .setLDAPUserDN(LDAP_USERDN)
                .setLDAPPassword("Bad Password")
                .setLDAPUrl(LDAP_URL)
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        loginPage = systemSettingsPage.logout()
                .loginInvalid(LDAP_USERNAME, LDAP_USERPASSWORD);

        assertTrue("Valid LDAP user was able to login using invalid LDAP settings.", loginPage.isLoginErrorPresent());
    }

    @Test
    public void testValidLDAPUserAndWipedSystemSettings() {
        systemSettingsPage.expandLDAPSettings()
                .setLDAPSearchBase(LDAP_SEARCHBASE)
                .setLDAPUserDN(LDAP_USERDN)
                .setLDAPPassword(LDAP_PASSWORD)
                .setLDAPUrl(LDAP_URL)
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        DashboardPage dashboardPage = systemSettingsPage.logout()
                .login(LDAP_USERNAME, LDAP_USERPASSWORD);

        assertTrue("Valid LDAP user was unable to login using valid LDAP settings.", dashboardPage.isLoggedin());

        systemSettingsPage = dashboardPage.logout()
                .defaultLogin()
                .clickSystemSettingsLink()
                .expandLDAPSettings()
                .setLDAPSearchBase("")
                .setLDAPUserDN("")
                .setLDAPPassword("")
                .setLDAPUrl("")
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        loginPage = systemSettingsPage.logout()
                .loginInvalid(LDAP_USERNAME, LDAP_PASSWORD);

        assertTrue("LDAP user was able to log in after LDAP credentials were cleared from System Settings.",
                loginPage.isLoginErrorPresent());
    }

    @Test
    public void testDefaultLDAPRole() {
        systemSettingsPage.expandLDAPSettings()
                .setLDAPSearchBase(LDAP_SEARCHBASE)
                .setLDAPUserDN(LDAP_USERDN)
                .setLDAPPassword(LDAP_PASSWORD)
                .setLDAPUrl(LDAP_URL)
                .clickSaveChanges();

        systemSettingsPage = systemSettingsPage.expandDefaultLDAPRole()
                .toggleDefaultRoleCheckbox()
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        DashboardPage dashboardPage = systemSettingsPage.logout()
                .login(LDAP_USERNAME, LDAP_USERPASSWORD);

        assertTrue("Alert was not shown on dashboard page.", dashboardPage.isPermissionsAlertDisplayed());

        systemSettingsPage = dashboardPage.logout()
                .defaultLogin()
                .clickSystemSettingsLink()
                .expandDefaultLDAPRole()
                .toggleDefaultRoleCheckbox()
                .setRole("Administrator")
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        dashboardPage = systemSettingsPage.logout()
                .login(LDAP_USERNAME, LDAP_USERPASSWORD);

        assertFalse("Alert was shown on dashboard page and should not have been.", dashboardPage.isPermissionsAlertDisplayed());
    }

    @Test
    public void testReadAccessLDAPRole() {
        systemSettingsPage.expandLDAPSettings()
                .setLDAPSearchBase(LDAP_SEARCHBASE)
                .setLDAPUserDN(LDAP_USERDN)
                .setLDAPPassword(LDAP_PASSWORD)
                .setLDAPUrl(LDAP_URL)
                .clickSaveChanges();

        systemSettingsPage = systemSettingsPage.expandDefaultLDAPRole()
                .setRole("Read Access")
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        TeamIndexPage teamIndexPage = systemSettingsPage.logout()
                .login(LDAP_USERNAME, LDAP_USERPASSWORD)
                .clickTeamsTab();

        assertTrue("The error Log wasn't showed", teamIndexPage.errorAlert().
                contains("You don't have permission to access any ThreadFix applications or to create one for yourself." +
                        " Contact your administrator to get help."));
    }

    @Test
    public void testSessionTimeout() {
        systemSettingsPage.expandSessionTimeoutSettings()
                .setTimeout("1")
                .clickSaveChanges();

        assertTrue("Save validation alert was not present." ,systemSettingsPage.isSaveSuccessful());

        systemSettingsPage.logout()
                .defaultLogin()
                .clickOrganizationHeaderLink();

        sleep(63000);

        DashboardPage dashboardPage = systemSettingsPage.clickDashboardLink();

        assertFalse("Session was still valid.", dashboardPage.isLoggedin());

        loginPage.defaultLogin().clickSystemSettingsLink()
                .expandSessionTimeoutSettings()
                .setTimeout("30")
                .clickSaveChanges();
    }
}
