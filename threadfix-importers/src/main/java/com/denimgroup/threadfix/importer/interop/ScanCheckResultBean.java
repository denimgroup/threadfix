package com.denimgroup.threadfix.importer.interop;

import java.util.Calendar;

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
