package com.denimgroup.threadfix.service;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.ScheduledEmailReportDao;
import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledEmailReportScheduler;

@Service
@Transactional(readOnly = false)
public class ScheduledEmailReportServiceImpl extends ScheduledJobServiceImpl<ScheduledEmailReport> implements ScheduledEmailReportService {

	private final SanitizedLogger log = new SanitizedLogger(ScheduledEmailReportServiceImpl.class);

	@Autowired
	private ScheduledEmailReportDao scheduledEmailReportDao;
	@Autowired
	private OrganizationDao organizationService;
	@Autowired
	private GenericSeverityDao genericSeverityDao;
	@Autowired
	ScheduledEmailReportScheduler scheduledEmailReportScheduler;


	@Override
	protected ScheduledJobDao<ScheduledEmailReport> getScheduledJobDao() {
		return scheduledEmailReportDao;
	}

	@Override
	public ScheduledEmailReport getDefaultScheduledJob() {
		return null;
	}

	@Override
	public void validateScheduleEmailReport(ScheduledEmailReport scheduledEmailReport, BindingResult result) {
		if (scheduledEmailReport.getSeverityLevel() == null || scheduledEmailReport.getSeverityLevel().getId() == null) {
			result.rejectValue("severityLevel", null, null, "invalid severity level");
			return;
		}

		if (scheduledEmailReport.getOrganizations() == null || scheduledEmailReport.getOrganizations().isEmpty()) {
			result.rejectValue("organizations", null, null, "At least one team must be selected");
			return;
		}

		List<Organization> organizations = scheduledEmailReport.getOrganizations();
		GenericSeverity severityLevel = scheduledEmailReport.getSeverityLevel();

		List<Organization> dbOrganizations = list();

		for (Organization organization : organizations){
			if (organization.getId()==null){
				result.rejectValue("organizations", null, null, "invalid inputs");
				return;
			}
			Organization dbOrganization = organizationService.retrieveById(organization.getId());
			if (dbOrganization==null || !dbOrganization.isActive()){
				result.rejectValue("organizations", null, null, "invalid inputs");
				return;
			}
			dbOrganizations.add(dbOrganization);
		}
		scheduledEmailReport.setOrganizations(dbOrganizations);

		GenericSeverity dbGenericSeverity = genericSeverityDao.retrieveById(severityLevel.getId());
		if (dbGenericSeverity!=null) {
			scheduledEmailReport.setSeverityLevel(dbGenericSeverity);
		}
		else {
			result.rejectValue("severityLevel.id", null, null, "invalid severity level");
			return;
		}
	}

	@Override
	public String addJobToScheduler(ScheduledEmailReport newScheduledEmailReport) {
		//Add new job to scheduler
		if (scheduledEmailReportScheduler.addScheduledJob(newScheduledEmailReport)) {
			log.info("Successfully added new scheduled email report to scheduler");
			return null;
		}
		else {
			log.warn("Failed to add new scheduled email report to scheduler");
			String message = "Adding new "+ newScheduledEmailReport.getFrequency() +
					" Email Report failed.";
			return message;
		}
	}

	@Override
	public String removeJobFromScheduler(ScheduledEmailReport oldScheduledEmailReport) {
		if (scheduledEmailReportScheduler.removeScheduledJob(oldScheduledEmailReport)) {
			log.info("Successfully deleted old scheduled email report from scheduler");
			return null;
		}
		else {
			String message = "Failed to delete " + oldScheduledEmailReport.getFrequency() + " Email Report from scheduler";
			log.warn(message);
			return message;
		}
	}

	@Override
	public String replaceJobFromScheduler(ScheduledEmailReport oldScheduledEmailReport, ScheduledEmailReport newScheduledEmailReport) {
		String removeResult = removeJobFromScheduler(oldScheduledEmailReport);
		if (removeResult!=null){
			return removeResult;
		}
		String addResult = addJobToScheduler(newScheduledEmailReport);
		if (addResult!=null){
				return addResult;
		}
		return null;
	}

	@Override
	public void removeTeam(ScheduledEmailReport scheduledEmailReport, Organization organization) {
		if (scheduledEmailReport.getOrganizations() != null && scheduledEmailReport.getOrganizations().contains(organization)) {
			scheduledEmailReport.getOrganizations().remove(organization);
			if (scheduledEmailReport.getOrganizations().isEmpty()) {
				String resultMessage = removeJobFromScheduler(scheduledEmailReport);
				if (resultMessage==null){
					delete(scheduledEmailReport);
				} else {
					log.warn(resultMessage);
				}
			} else {
				save(scheduledEmailReport);
			}

		}
	}
}
