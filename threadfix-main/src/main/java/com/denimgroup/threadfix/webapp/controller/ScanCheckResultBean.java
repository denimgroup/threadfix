package com.denimgroup.threadfix.webapp.controller;

import java.util.Calendar;

import com.denimgroup.threadfix.plugin.scanner.service.channel.ScanImportStatus;

public class ScanCheckResultBean {

	private ScanImportStatus scanCheckResult;
	private Calendar testDate;
	
	public ScanCheckResultBean(ScanImportStatus scanCheckResult, Calendar testDate) {
		this.scanCheckResult = scanCheckResult;
		this.testDate = testDate;
	}
	
	public ScanCheckResultBean(ScanImportStatus scanCheckResult) {
		this.scanCheckResult = scanCheckResult;
	}

	public Calendar getTestDate() {
		return testDate;
	}
	
	public ScanImportStatus getScanCheckResult() {
		return scanCheckResult;
	}
}
