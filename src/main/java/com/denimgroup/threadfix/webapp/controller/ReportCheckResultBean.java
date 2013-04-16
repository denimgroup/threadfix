package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;

public class ReportCheckResultBean {
	private StringBuffer report;
	private ReportCheckResult reportCheckResult;
	
	public ReportCheckResultBean(ReportCheckResult reportCheckResult, StringBuffer report) {
		this.report = report;
		this.reportCheckResult = reportCheckResult;
	}
	
	public StringBuffer getReport() { return report; }
	public ReportCheckResult getReportCheckResult() { return reportCheckResult; }
}