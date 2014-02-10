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