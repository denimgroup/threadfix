package com.denimgroup.threadfix.webapp.controller;

import java.util.Calendar;

public class ScanCheckResultBean {

	private String scanCheckResult;
	private Calendar testDate;
	
	public ScanCheckResultBean(String scanCheckResult, Calendar testDate) {
		this.scanCheckResult = scanCheckResult;
		this.testDate = testDate;
	}
	
	public ScanCheckResultBean(String scanCheckResult) {
		this.scanCheckResult = scanCheckResult;
	}

	public Calendar getTestDate() {
		return testDate;
	}
	public void setTestDate(Calendar testDate) {
		this.testDate = testDate;
	}
	
	public String getScanCheckResult() {
		return scanCheckResult;
	}
	public void setScanCheckResult(String scanCheckResult) {
		this.scanCheckResult = scanCheckResult;
	}
}
