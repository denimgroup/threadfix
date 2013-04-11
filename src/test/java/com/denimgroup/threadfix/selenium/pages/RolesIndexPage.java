package com.denimgroup.threadfix.selenium.pages;

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RolesIndexPage extends BasePage {

	private WebElement createNewRoleLink;
	
	private List<WebElement> names = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();

	public RolesIndexPage(WebDriver webdriver) {
		super(webdriver);
		createNewRoleLink = driver.findElementById("createRoleModalLink");
		
		for (int i = 1; i <= getNumRows(); i++) {
			names.add(driver.findElementById("role" + i));
			editLinks.add(driver.findElementById("editModalLink" + i));
			deleteButtons.add(driver.findElementById("delete" + i));
		}
	}
		
	public RoleCreatePage clickCreateRoleLink() {
		createNewRoleLink.click();
		return new RoleCreatePage(driver);
	}
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("roleRow");
		if (bodyRows != null && bodyRows.size() == 1 && 
				bodyRows.get(0).getText().trim().equals("No roles found.")) {
			return 0;
		}		
		
		return bodyRows.size();
	}
	
	public String getNameContents(int row) {
		return names.get(row).getText();
	}
	
	public RolesIndexPage clickDeleteButton(int row) {
		deleteButtons.get(row).click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickDeleteButton(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	private int getIndex(String roleName) {
		int i = 0;
		for (WebElement name : names) {
			if (name.getText().equals(roleName)) {
				return i;
			}
			i++;
		}
		return 0;
	}
	
	public RolesIndexPage clickCreateRole(){
		driver.findElementById("createRoleModalLink").click();
		waitForElement(driver.findElementById("createRoleModal"));
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage createRole(String displayName) {
		
		
		
		if (displayName != null) {
			setRoleName(displayName);
			
		}
		
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage setRoleName(String name){
		List<WebElement> dName = driver.findElementsById("displayName");
		dName.get(dName.size()-1).clear();
		dName.get(dName.size()-1).sendKeys(name);
		return new RolesIndexPage(driver);
	}
	public RolesIndexPage setRoleName(String name,int row){
		List<WebElement> dName = driver.findElementsById("displayName");
		dName.get(row).clear();
		dName.get(row).sendKeys(name);
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickSaveRole(){ 
		List<WebElement> sBtn = driver.findElementsById("newRoleFormSubmitButton");
		sBtn.get(sBtn.size()-1).click();
		waitForInvisibleElement(driver.findElementById("createRoleModal"));
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickSaveRole(int row){ 
		List<WebElement> sBtn = driver.findElementsById("submitRemoteProviderFormButton");
		sBtn.get(row).click();
		//waitForInvisibleElement(driver.findElementById("createRoleModal"));
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickEditLink(int row) {
		editLinks.get(row).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickEditLink(String roleName) {
		editLinks.get(names.indexOf(roleName)).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickUpdateRoleButton(int row) {
		driver.findElementsById("submitRemoteProviderFormButton").get(row).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickCreateRoleButtonInvalid() {
		driver.findElementById("newRoleFormSubmitButton").click();
		return new RolesIndexPage(driver);
	}

	public String getDisplayNameError() {
		return driver.findElementById("displayName.errors").getText();
	}
	
	public boolean getPermissionValue(String permissionName) {
		return driver.findElementById("newRoleModalBody").findElement(By.id(permissionName + "True")).isSelected();
	}
	
	public boolean getPermissionValue(String permissionName, int row) {
		return driver.findElementById("editRoleModal"+(row+1)).findElement(By.id(permissionName + "True")).isSelected();
	}
	
	public RolesIndexPage setPermissionValue(String permissionName, boolean value) {
		String target = value ? "True" : "False";
		driver.findElementById("newRoleModalBody").findElement(By.id(permissionName + target)).click();
		
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage setPermissionValue(String permissionName, boolean value,int row) {
		String target = value ? "True" : "False";
		driver.findElementById("editRoleModal"+(row+1)).findElement(By.id(permissionName + target)).click();
		
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickSaveRole(String name) {
		driver.findElementsById("submitRemoteProviderFormButton").get(names.indexOf(name)).click();
		return new RolesIndexPage(driver);
	}

	public String getAlert() {
		return driver.findElementByClassName("alert-error").getText();
	}
	
	public RolesIndexPage clickCloseModal(int row){
		driver.findElementsByClassName("close").get(row).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickUpdateRoleButtonInvalid(int row) {
		driver.findElementsById("submitRemoteProviderFormButton").get(row).click();
		return new RolesIndexPage(driver);
	}
}
