////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.report;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.ui.Model;

import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;


/**
 * @author drivera
 * 
 */
public interface ReportsService {
	
	enum ReportCheckResult {
		VALID("Valid"), NO_APPLICATIONS("No Applications"), BAD_REPORT_TYPE("Bad Report Type"), IO_ERROR("IO Error");
		
		private String text;
		
		ReportCheckResult(String text) { this.text = text; }
		public String toString() { return text; }
	}
	
	public enum ReportFormat { 
		BAD_FORMAT(""),
		TRENDING("trending.jrxml"), 
		POINT_IN_TIME("pointInTime.jrxml"), 
		VULNERABILITY_PROGRESS_BY_TYPE("cwe.jrxml"), 
		CHANNEL_COMPARISON_BY_VULN_TYPE("cweChannel.jrxml"), 
		CHANNEL_COMPARISON_SUMMARY("scannerComparison.jrxml"), 
		CHANNEL_COMPARISON_DETAIL("scannerComparisonByVulnerability"), 
		MONTHLY_PROGRESS_REPORT("monthlyBarChart.jrxml"),
		SIX_MONTH_SUMMARY("sixMonthSummary.jrxml"),
		TWELVE_MONTH_SUMMARY("twelveMonthSummary.jrxml"),
		PORTFOLIO_REPORT("portfolioReport"),
		TOP_TEN_APPS("topTenApps.jrxml"),
		TOP_TWENTY_APPS("topTwentyApps.jrxml"),
		POINT_IN_TIME_GRAPH("pointInTimeGraph.jrxml");
		
		private String fileName;
		
		ReportFormat(String fileName) { this.fileName = fileName; }
		public String getFileName() { return fileName; }
	}

	ReportCheckResultBean generateReport(ReportParameters parameters, 
			HttpServletRequest request, HttpServletResponse response);

	String scannerComparisonByVulnerability(Model model,
			ReportParameters reportParameters);

}
