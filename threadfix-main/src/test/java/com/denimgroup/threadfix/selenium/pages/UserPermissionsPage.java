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

package com.denimgroup.threadfix.selenium.pages;


import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class UserPermissionsPage extends BasePage {

	public UserPermissionsPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public UserPermissionsPage clickAddPermissionsLink(){
		driver.findElementById("addPermissionButton").click();
		waitForElement(driver.findElementById("myModalLabel"));
		sleep(3000);
		return new UserPermissionsPage(driver);
	}
	
	public UserPermissionsPage setTeam(String team){
		new Select(driver.findElement(By.id("orgSelect"))).selectByVisibleText(team);
		return this;
	}

    //Note, the default is that all apps is selected
    public UserPermissionsPage toggleAllApps() {
        driver.findElementById("allAppsCheckbox").click();
        return this;
    }

    public UserPermissionsPage setTeamRole(String role) {
        new Select(driver.findElementById("roleSelectTeam")).selectByVisibleText(role);
        return this;
    }

    //TODO, fix when new ids hit
    public UserPermissionsPage setApplicationRole(String appName, String role) {
        return this;
    }

	public int numOfAppsNewPerm(){
		return driver.findElementsById("myModal").get(0).findElement(By.id("appSelect"))
															.findElements(By.tagName("tr")).size();
	}
	public UserPermissionsPage selectAppNewPerm(String appName){
		int cnt = numOfAppsNewPerm();
		for (int i = 1; i<=cnt; i++){
			if(driver.findElementsById("myModal").get(0).findElement(By.id("appSelect"))
						.findElement(By.id("applicationName"+i)).getText().contains(appName)){
				
				driver.findElementsById("myModal").get(0).findElement(By.id("appSelect"))
												.findElement(By.id("applicationIds"+i)).click();
				
				break;
			}
		}
		
		return new UserPermissionsPage(driver);
		
	}
	
	public UserPermissionsPage selectAppRoleNewPerm(String appName,String role){
		int cnt = numOfAppsNewPerm();
		for (int i = 1; i<=cnt; i++){
			if(driver.findElementsById("myModal").get(0).findElement(By.id("appSelect"))
						.findElement(By.id("applicationName"+i)).getText().contains(appName)){
				
				new Select(driver.findElementsById("myModal").get(0).findElement(By.id("appSelect"))
												.findElement(By.id("roleSelect"+i))).selectByVisibleText(role);
				
				break;
			}
		}
		return new UserPermissionsPage(driver);
	}
	
	public UserPermissionsPage clickAddMappingNewPerm(){
		driver.findElementsById("myModal").get(0).findElement(By.id("submitModalAdd")).click();
		sleep(3000);
		return new UserPermissionsPage(driver);
	}


    public boolean isErrorPresent(String errorMessage) {
        return driver.findElementByClassName("errors").getText().contains(errorMessage);
    }
}
