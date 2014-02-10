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
package com.denimgroup.threadfix.data.entities;

import java.io.Serializable;

public class ReportParameters implements Serializable {
	
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
		TOP_TEN_VULNS("topTenVulns.jrxml"),
		POINT_IN_TIME_GRAPH("pointInTimeGraph.jrxml"),
		VULNERABILITY_LIST("vulnerabilityList");
		
		private String fileName;
		
		ReportFormat(String fileName) { this.fileName = fileName; }
		public String getFileName() { return fileName; }
	}

	private static final long serialVersionUID = -1005210910671815370L;

	private int organizationId;
	private int applicationId;
	private int reportId;
	private int formatId;
	private ReportFormat reportFormat;

	public ReportParameters() {
		this.organizationId = 0;
		this.applicationId = 0;
		this.reportId = 0;
		this.formatId = 0;
	}

	public ReportParameters(int organizationId, int applicationId, int reportId) {
		this.organizationId = organizationId;
		this.applicationId = applicationId;
		this.reportId = reportId;
	}

	public int getOrganizationId() {
		return organizationId;
	}

	public void setOrganizationId(int organizationId) {
		this.organizationId = organizationId;
	}

	public int getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(int applicationId) {
		this.applicationId = applicationId;
	}

	public int getReportId() {
		return reportId;
	}

	public void setReportId(int reportId) {
		this.reportId = reportId;
	}
	
	public int getFormatId() {
		return formatId;
	}

	public void setFormatId(int formatId) {
		this.formatId = formatId;
	}
	
	private static final ReportFormat[] REPORTS = { ReportFormat.BAD_FORMAT, 
		ReportFormat.TRENDING,
		ReportFormat.POINT_IN_TIME, 
		ReportFormat.VULNERABILITY_PROGRESS_BY_TYPE, 
		ReportFormat.CHANNEL_COMPARISON_BY_VULN_TYPE, 
		ReportFormat.CHANNEL_COMPARISON_SUMMARY,
		ReportFormat.CHANNEL_COMPARISON_DETAIL, 
		ReportFormat.MONTHLY_PROGRESS_REPORT,
		ReportFormat.PORTFOLIO_REPORT, 
		ReportFormat.TWELVE_MONTH_SUMMARY, 
		ReportFormat.TOP_TWENTY_APPS,
		ReportFormat.VULNERABILITY_LIST};
	
	// Translate reportId to the appropriate enum
	public ReportFormat getReportFormat() {
		if (reportFormat == null) {
			if (getReportId() < 0 || getReportId() > REPORTS.length - 1 ||
				REPORTS[getReportId()] == null) {
				return ReportFormat.BAD_FORMAT;
			} else {
				return REPORTS[getReportId()];
			}
		} else {
			return reportFormat;
		}
	}
	
	public void setReportFormat(ReportFormat format) {
		this.reportFormat = format;
	}
}
