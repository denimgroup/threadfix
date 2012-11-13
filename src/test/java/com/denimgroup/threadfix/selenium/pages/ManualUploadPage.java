////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class ManualUploadPage extends BasePage {
	private WebElement dynamicBtn;
	private WebElement staticBtn;
	private WebElement cweText;
	private WebElement urlText;
	private WebElement lineNumber;
	private WebElement sourceFile;
	
	private WebElement paramText;
	private Select severity;
	private WebElement descText;
	private WebElement submitBtn;
	private WebElement StatSubmitBtn;
	private WebElement backLink;

	public ManualUploadPage(WebDriver webdriver) {
		super(webdriver);
		dynamicBtn = driver.findElementById("dynamicRadioButton");
		staticBtn = driver.findElementById("staticRadioButton");
		cweText = driver.findElementById("txtSearch");
		urlText = driver.findElementById("urlDynamicSearch");
		
		paramText = driver.findElementById("parameterInput");
		severity = new Select(driver.findElementById("severityInput"));
		descText = driver.findElementById("descriptionInput");
		submitBtn = driver.findElementById("dynamicSubmit");
		StatSubmitBtn = driver.findElementById("staticSubmit");
		backLink = driver.findElementById("backToAppLink");
	}
	
	public ManualUploadPage setCWE(String Status) {
		cweText.clear();
		cweText.sendKeys(Status);
		return this;
	}
	
	public ManualUploadPage setURL(String Status) {
		urlText.clear();
		urlText.sendKeys(Status);
		return this;
	}
	
	public ManualUploadPage setParameter(String Status) {
		paramText.clear();
		paramText.sendKeys(Status);
		return this;
	}
	
	public ManualUploadPage setDescription(String Status) {
		descText.clear();
		descText.sendKeys(Status);
		return this;
	}
	
	public String selectSeverityList(String text) {
		severity.selectByVisibleText(text);
		return severity.getFirstSelectedOption().getText();
	}

	public ApplicationDetailPage clickSubmit() {
		submitBtn.click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickStaticSubmit() {
		StatSubmitBtn.click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickBack() {
		backLink.click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	// Dynamic Button
	public void setDynamicRadiobtn(Boolean isDynamicRadioBtn) {
		if (getDynamicRadiobtn().isSelected() && !isDynamicRadioBtn)
			getDynamicRadiobtn().click();
		else if (!getDynamicRadiobtn().isSelected() && isDynamicRadioBtn)
			getDynamicRadiobtn().click();
	}

	public void setDynamicRadioBtn(WebElement DynamicRadioBtn) {
		dynamicBtn = DynamicRadioBtn;
	}

	public WebElement getDynamicRadiobtn() {
		return dynamicBtn;
	}

	public ApplicationDetailPage fillAllClickSaveManual(Boolean dynamicRadioButton, String cwe, String url, 
			String param, String severity, String description) {
		fillRequiredManual(cwe, url, param, severity,description);
		clickSubmit();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage fillRequiredManual(String cwe, String url, String param, String severity, String description) {
		setCWE(cwe);
		setURL(url);
		setParameter(param);
		selectSeverityList(severity);
		setDescription(description);
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public ManualUploadPage setStaticRadiobtn(Boolean isStaticRadioBtn) {

		if (getStaticRadioButton().isSelected() && !isStaticRadioBtn)
			getStaticRadioButton().click();
		else if (!getStaticRadioButton().isSelected() && isStaticRadioBtn)
			getStaticRadioButton().click();
	
		return this;
	}


	public ManualUploadPage setStaticRadioBtn(WebElement staticRadioBtn) {
		staticBtn = staticRadioBtn;
		return this;
	}

	public WebElement getStaticRadioButton() {
		return staticBtn;
	}
	
	public ManualUploadPage setLineNumber(String LineNo) {
		if (getStaticRadioButton().isSelected()) {
			lineNumber = driver.findElementById("urlSearch");
			lineNumber.clear();
			lineNumber.sendKeys(LineNo);
		}
		return this;
	}
	
	public ManualUploadPage setSourceFile(String sourcefile) {
		if (getStaticRadioButton().isSelected()) {
			sourceFile = driver.findElementById("urlStaticSearch");
			sourceFile.clear();
			sourceFile.sendKeys(sourcefile);
		}
		return this;
	}
	
	public void fillAllClickSaveStatic(Boolean staticRadioBtn, String cwe,
			String sourceFile, String lineNumber, String param,
			String severity, String description) {
		fillRequiredStatic(staticRadioBtn,cwe, sourceFile,lineNumber, param, severity,description);
		
		clickStaticSubmit();
		sleep(1000);
	}
	
	public ApplicationDetailPage fillRequiredStatic(Boolean staticRadioBtn, String cwe,
			String sourceFile, String lineNumber, String param,
			String severity, String description) {
		setStaticRadiobtn(staticRadioBtn);
		setCWE(cwe);
		setSourceFile(sourceFile);
		setLineNumber(lineNumber);
		setParameter(param);
		selectSeverityList(severity);
		setDescription(description);
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
}
