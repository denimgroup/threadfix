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

import com.denimgroup.threadfix.selenium.pages.*;
import org.junit.Test;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.Assert.assertTrue;

import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;

public class DocumentTests extends BaseTest {

	public String appWasAlreadyUploadedErrorText = "Scan file has already been uploaded.";
	private static Map<String, String> fileMap = ScanContents.SCAN_FILE_MAP;
	
	@Test
	public void testUploadScans() throws MalformedURLException {
		String teamName = "uploadDocTeam" + getRandomString(3);
		String appName = "uploadDocApp" + getRandomString(3);
        File appScanFile;
        int docCnt  = 0;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
		
		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}
			applicationDetailPage = applicationDetailPage.clickDocumentTab()
                    .clickUploadDocLink()
                    .setDocFileInput(mapEntry.getValue())
                    .submitDoc();

			applicationDetailPage = applicationDetailPage.clickDocumentTab();
			docCnt++;
		}
		assertTrue("Document count is incorrect", docCnt == applicationDetailPage.docsCount());
	}
}
