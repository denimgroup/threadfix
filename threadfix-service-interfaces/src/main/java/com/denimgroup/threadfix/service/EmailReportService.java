package com.denimgroup.threadfix.service;

import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.data.entities.AcceptanceCriteria;
import com.denimgroup.threadfix.data.entities.AcceptanceCriteriaStatus;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public interface EmailReportService {

	public void sendEmailReport(ScheduledEmailReport scheduledEmailReport);

	public List<Vulnerability> getNewVulnerabilities(ScheduledEmailReport scheduledEmailReport);

	public String getEmailReportBody(ScheduledEmailReport scheduledEmailReport);

	public String getEmailReportSubject(List<Vulnerability> vulnerabilities);

	public Map<String, Object> getNewVulnerabilitiesHierarchicalModel(ScheduledEmailReport scheduledEmailReport);

    public void sendAcceptanceCriteriaReport(List<AcceptanceCriteriaStatus> acceptanceCriteriaStatuses);
}
