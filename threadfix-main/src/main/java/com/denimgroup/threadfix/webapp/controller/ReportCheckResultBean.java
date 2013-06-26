package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;

public class ReportCheckResultBean {
	private StringBuffer report = null;
	private byte[] reportBytes = null;
	private ReportCheckResult reportCheckResult = null;
	
	public ReportCheckResultBean(ReportCheckResult reportCheckResult) {
		this.reportCheckResult = reportCheckResult;
	}
	
	public ReportCheckResultBean(ReportCheckResult reportCheckResult, 
			StringBuffer report, byte[] reportBytes) {
		this.report = report;
		this.reportCheckResult = reportCheckResult;
		this.reportBytes = reportBytes;
	}
	
	public byte[] getReportBytes() { return reportBytes; }
	public StringBuffer getReport() { return report; }
	public ReportCheckResult getReportCheckResult() { return reportCheckResult; }
	
	@Override
	public String toString() {
		return "Report Check: { status: " + reportCheckResult.toString() + 
				", report: " + (report == null && reportBytes == null ? " empty }" : " not empty }");
	}
}