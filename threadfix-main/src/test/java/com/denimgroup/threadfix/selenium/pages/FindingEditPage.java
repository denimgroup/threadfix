package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class FindingEditPage extends BasePage {
	private WebElement staticButton;
	private WebElement dynamicButton;
	private WebElement cweText;
	private WebElement urlText;
	private WebElement lineNumber;
	private WebElement sourceFile;
	
	private WebElement paramText;
	private Select severity;
	private WebElement descText;
	private WebElement dynamicSubmitButton;
	private WebElement backLink;

	public FindingEditPage(WebDriver webdriver) {
		super(webdriver);
//		dynamicButton = driver.findElementById("dynamicRadioButton");
//		staticButton = driver.findElementById("staticRadioButton");
//		cweText = driver.findElementById("txtSearch");
//		urlText = driver.findElementById("urlDynamicSearch");
//		paramText = driver.findElementById("parameterInput");
//		severity = new Select(driver.findElementById("severityInput"));
//		descText = driver.findElementById("descriptionInput");
//		dynamicSubmitButton = driver.findElementById("dynamicSubmit");
//		backLink = driver.findElementById("backToAppLink");
	}
	
	public FindingEditPage clickDynamicRadioButton() {
		if (!dynamicButton.isSelected())
			dynamicButton.click();
		return this;
	}
	
	public FindingEditPage clickStaticRadioButton() {
		if (!staticButton.isSelected())
			staticButton.click();
		return this;
	}
	
	public FindingEditPage setCWE(String status) {
		cweText.clear();
		cweText.sendKeys(status + "\n");
		return new FindingEditPage(driver);
	}
	
	public String getCWE() {
		return cweText.getAttribute("value");
	}
	
	public FindingEditPage setURL(String status) {
		urlText.clear();
		urlText.sendKeys(status);
		return this;
	}

	public String getURL() {
		return urlText.getAttribute("value");
	}
	
	public FindingEditPage setParameter(String status) {
		paramText.clear();
		paramText.sendKeys(status);
		return this;
	}

	public String getParameter() {
		return paramText.getAttribute("value");
	}
	
	public FindingEditPage setDescription(String status) {
		descText.clear();
		descText.sendKeys(status);
		return this;
	}

	public String getDescription() {
		return descText.getText();
	}
	
	public FindingEditPage selectSeverityList(String text) {
		severity.selectByVisibleText(text);
		return this;
	}

	public String getSeverity() {
		return severity.getFirstSelectedOption().getText();
	}
	
	public ApplicationDetailPage clickBack() {
		backLink.click();
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage clickDynamicSubmit() {
		dynamicSubmitButton.click();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage clickStaticSubmit() {
		driver.findElementById("staticSubmit").click();
		return new ApplicationDetailPage(driver);
	}
	
	public FindingEditPage clickDynamicSubmitInvalid() {
		dynamicSubmitButton.click();
		return new FindingEditPage(driver);
	}
	
	public FindingEditPage clickStaticSubmitInvalid() {
		driver.findElementById("staticSubmit").click();
		return new FindingEditPage(driver);
	}
	
	public String getChannelVulnError() {
		return driver.findElementById("channelVulnerability.code.errors").getText();
	}
	
	public String getDescriptionError() {
		return driver.findElementById("longDescription.errors").getText();
	}
	
	public ApplicationDetailPage fillAllClickSaveDynamic(Boolean dynamicRadioButton, String cwe, String url, 
			String param, String severity, String description) {
		clickDynamicRadioButton();
		fillRequiredDynamic(cwe, url, param, severity,description);
		clickDynamicSubmit();
		return new ApplicationDetailPage(driver);
	}
	
	public ApplicationDetailPage fillAllClickSaveStatic(Boolean staticRadioBtn, String cwe,
			String sourceFile, String lineNumber, String param,
			String severity, String description) {
		clickStaticRadioButton();
		fillRequiredStatic(staticRadioBtn,cwe, sourceFile,lineNumber, param, severity,description);
		clickStaticSubmit();
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage fillRequiredDynamic(String cwe, String url, String param, String severity, String description) {
		setCWE(cwe);
		setURL(url);
		setParameter(param);
		selectSeverityList(severity);
		setDescription(description);
		return new ApplicationDetailPage(driver);
	}

	public ApplicationDetailPage fillRequiredStatic(Boolean staticRadioBtn, String cwe,
			String sourceFile, String lineNumber, String param,
			String severity, String description) {
		setCWE(cwe);
		setSourceFile(sourceFile);
		setLineNumber(lineNumber);
		setParameter(param);
		selectSeverityList(severity);
		setDescription(description);
		return new ApplicationDetailPage(driver);
	}

	public FindingEditPage setLineNumber(String lineNo) {
		if (staticButton.isSelected()) {
			lineNumber = driver.findElementById("urlSearch");
			lineNumber.clear();
			lineNumber.sendKeys(lineNo);
		}
		return this;
	}
	
	public String getLineNumber() {
		return driver.findElementById("urlSearch").getAttribute("value");
	}
	
	public String getLineNumberError() {
		return driver.findElementById("dataFlowElements0.errors").getText();
	}
	
	public FindingEditPage setSourceFile(String sourcefile) {
		if (staticButton.isSelected()) {
			sourceFile = driver.findElementById("urlStaticSearch");
			sourceFile.clear();
			sourceFile.sendKeys(sourcefile);
		}
		return this;
	}
	
	public String getSourceFile() {
		return driver.findElementById("urlStaticSearch").getAttribute("value");
	}
	
	public VulnerabilityDetailPage clickViewVuln(){
		driver.findElementsByClassName("btn").get(0).click();
		return new VulnerabilityDetailPage(driver);
	}
	
	public MergeFindingPage clickMergeFinding(){
		driver.findElementsByClassName("btn").get(0).click();
		return new MergeFindingPage(driver);
	}

}
