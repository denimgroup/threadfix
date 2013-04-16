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
	
	public int getIndex(String roleName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}
	
	public String getNameContents(int row) {
		return names.get(row).getText();
	}
		
	public RolesIndexPage clickDeleteButton(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	
	public RolesIndexPage clickCreateRole(){
		driver.findElementById("createRoleModalLink").click();
		waitForElement(driver.findElementById("createRoleModal"));
		return new RolesIndexPage(driver);
	}
	

	public RolesIndexPage setRoleName(String name,String oldName){
		if(oldName == null){
			driver.findElementsById("displayName").get(getNumRows()).clear();
			driver.findElementsById("displayName").get(getNumRows()).sendKeys(name);
		}else{
			driver.findElementsById("displayName").get(getIndex(oldName)).clear();
			driver.findElementsById("displayName").get(getIndex(oldName)).sendKeys(name);
		}
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickSaveRole(String oldName){ 
		if(oldName == null){
			driver.findElementById("newRoleFormSubmitButton").click();
			waitForInvisibleElement(driver.findElementById("createRoleModal"));
		}else{
			driver.findElementsById("submitRemoteProviderFormButton").get(getIndex(oldName)).click();
			waitForInvisibleElement(driver.findElementByClassName("modal"));
		}
		return new RolesIndexPage(driver);
	}
		

	public RolesIndexPage clickEditLink(String oldName) {
		editLinks.get(names.indexOf(oldName)).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickCreateRoleButtonInvalid() {
		clickSaveRole(null);
		return new RolesIndexPage(driver);
	}

	public String getDisplayNameError() {
		return driver.findElementByClassName("alert-error").getText();
	}
	
	public boolean getNewPermissionValue(String permissionName) {
		return driver.findElementById("newRoleModalBody").findElement(By.id(permissionName + "True")).isSelected();
	}
	
	public boolean getPermissionValue(String permissionName, String oldName) {
		return driver.findElementById("editRoleModal"+(getIndex(oldName))).findElement(By.id(permissionName + "True")).isSelected();
	}
	
	public RolesIndexPage setNewPermissionValue(String permissionName, boolean value) {
		String target = value ? "True" : "False";
		driver.findElementById("newRoleModalBody").findElement(By.id(permissionName + target)).click();
		
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage setPermissionValue(String permissionName, boolean value,String oldName) {
		String target = value ? "True" : "False";
		driver.findElementById("editRoleModal"+(getIndex(oldName))).findElement(By.id(permissionName + target)).click();
		
		return new RolesIndexPage(driver);
	}

	
	public RolesIndexPage clickCloseModal(){
		driver.findElementByClassName("modal-footer").findElement(By.className("btn")).click();
		return new RolesIndexPage(driver);
	}

	public RolesIndexPage clickUpdateRoleButtonInvalid(int row) {
		driver.findElementsById("submitRemoteProviderFormButton").get(row).click();
		return new RolesIndexPage(driver);
	}
	
	public boolean isCreateValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Role "+role+" was created successfully.");
	}
	
	public boolean isEditValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Role "+role+" was edited successfully.");
	}
	
	public boolean isDeleteValidationPresent(String role){
		return driver.findElementByClassName("alert-success").getText().contains("Role "+role+" was deleted successfully.");
	}
}
