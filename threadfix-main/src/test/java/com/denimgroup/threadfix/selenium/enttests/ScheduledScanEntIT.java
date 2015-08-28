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
package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class ScheduledScanEntIT extends BaseDataTest {

    private ApplicationDetailPage applicationDetailPage;

    @Before
    public void initialize() {
        initializeTeamAndApp();

        applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScheduleScanTab(0);
    }

    @Test
    public void testScheduleDailyScan() {
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Daily")
                .setScheduledScanTime("8", "15", "PM")
                .setScheduledScanScanner("OWASP Zed Attack Proxy",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        applicationDetailPage.waitForModalToClose();

        assertTrue("Scan was not scheduled properly.", applicationDetailPage.isScheduledScanCountCorrect("1"));
    }

    @Test
    public void testValidDailyScan(){
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Daily")
                .setScheduledScanTime("8", "15", "PM")
                .setScheduledScanScanner("OWASP Zed Attack Proxy",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        boolean scanScanner = applicationDetailPage.getScheduledScanScanner().trim().equals("OWASP Zed Attack Proxy");
        boolean scanDay = applicationDetailPage.getScheduledScanDay().trim().equals("8:15 PM");
        boolean scanFrequency = applicationDetailPage.getScheduledScanFrequency().trim().equals("Daily");

        assertTrue("Daily scan validation failed", scanScanner && scanDay && scanFrequency);
    }

    @Test
    public void testDeleteDailyScan(){
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Daily")
                .setScheduledScanTime("8", "15", "PM")
                .setScheduledScanScanner("OWASP Zed Attack Proxy",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        applicationDetailPage.clickDeleteScheduledScan();
        sleep(2000);

        assertTrue("Scan was not deleted properly.", applicationDetailPage.isScheduledScanCountCorrect("0"));
    }

    @Test
    public void testScheduleWeeklyScan() {
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Weekly")
                .setScheduledScanTime("6", "30", "AM")
                .setScheduledScanDay("Friday")
                .setScheduledScanScanner("OWASP Zed Attack Proxy",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        assertTrue("Scan was not scheduled properly.", applicationDetailPage.isScheduledScanCountCorrect("1"));
    }

    @Test
    public void testValidWeeklyScan(){
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Weekly")
                .setScheduledScanTime("6", "30", "AM")
                .setScheduledScanDay("Friday")
                .setScheduledScanScanner("OWASP Zed Attack Proxy",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        boolean scanScanner = applicationDetailPage.getScheduledScanScanner().trim().equals("OWASP Zed Attack Proxy");
        boolean scanDay = applicationDetailPage.getScheduledScanDay().trim().equals("Friday 6:30 AM");
        boolean scanFrequency = applicationDetailPage.getScheduledScanFrequency().trim().equals("Weekly");

        assertTrue("Daily scan validation failed", scanScanner && scanDay && scanFrequency);
    }

    @Test
    public void testDeleteWeeklyScan(){
        applicationDetailPage.clickScheduleNewScanButton()
                .setScheduledScanFrequency("Weekly")
                .setScheduledScanTime("6", "30", "AM")
                .setScheduledScanDay("Friday")
                .setScheduledScanScanner("Burp Suite Pro",applicationDetailPage.getApplicationId())
                .clickModalSubmit();

        applicationDetailPage.clickDeleteScheduledScan();
        sleep(2000);

        assertTrue("Scan was not deleted properly.", applicationDetailPage.isScheduledScanCountCorrect("0"));
    }
}
