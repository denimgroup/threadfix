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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import net.sf.jasperreports.engine.JRException;
import net.sf.jasperreports.engine.JRExporter;
import net.sf.jasperreports.engine.JRExporterParameter;
import net.sf.jasperreports.engine.JRParameter;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperExportManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.design.JasperDesign;
import net.sf.jasperreports.engine.export.JRCsvExporter;
import net.sf.jasperreports.engine.export.JRHtmlExporter;
import net.sf.jasperreports.engine.export.JRHtmlExporterParameter;
import net.sf.jasperreports.engine.export.JRPdfExporter;
import net.sf.jasperreports.engine.xml.JRXmlLoader;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.PermissionUtils;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;

/**
 * @author mcollins
 * @author drivera
 * 
 */
@Service
public class ReportsServiceImpl implements ReportsService {
	
	private final SanitizedLogger log = new SanitizedLogger(ReportsServiceImpl.class);

	private SessionFactory sessionFactory = null;
	private ChannelTypeDao channelTypeDao = null;
	private ScanDao scanDao = null;
	private VulnerabilityDao vulnerabilityDao = null;
	private OrganizationDao organizationDao = null;
	private ApplicationDao applicationDao = null;
	private PermissionService permissionService = null;
	
	/**
	 * @param sessionFactory
	 */
	@Autowired
	public ReportsServiceImpl(SessionFactory sessionFactory, ChannelTypeDao channelTypeDao,
			PermissionService permissionService, OrganizationDao organizationDao,
			ScanDao scanDao, VulnerabilityDao vulnerabilityDao, ApplicationDao applicationDao) {
		this.sessionFactory = sessionFactory;
		this.channelTypeDao = channelTypeDao;
		this.scanDao = scanDao;
		this.organizationDao = organizationDao;
		this.permissionService = permissionService;
		this.vulnerabilityDao = vulnerabilityDao;
		this.applicationDao = applicationDao;
	}

	@Override
	public ReportCheckResultBean generateReport(ReportParameters parameters,
			HttpServletRequest request) {
		if (parameters.getReportFormat() == ReportFormat.BAD_FORMAT) {
			return new ReportCheckResultBean(ReportCheckResult.BAD_REPORT_TYPE);
		}
		
		List<Integer> applicationIdList = getApplicationIdList(parameters);
	
		if (applicationIdList == null || applicationIdList.isEmpty()) {
			return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
		}
		
		if (parameters.getReportFormat() == ReportFormat.VULNERABILITY_LIST) {
			StringBuffer dataExport = getDataVulnListReport(getListofRowParams(applicationIdList), applicationIdList);
			return new ReportCheckResultBean(ReportCheckResult.VALID, dataExport, null);
		}
		
		if (parameters.getReportFormat() == ReportFormat.TOP_TEN_APPS) {
			applicationIdList = applicationDao.getTopXVulnerableAppsFromList(10, applicationIdList);
		} else if (parameters.getReportFormat() == ReportFormat.TOP_TWENTY_APPS) {
			applicationIdList = applicationDao.getTopXVulnerableAppsFromList(20, applicationIdList);
		}
		
		if (applicationIdList == null || applicationIdList.isEmpty()) {
			return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
		}
		log.info("About to generate report for " + applicationIdList.size() + " applications.");

		Map<String, Object> params = new HashMap<>();
		params.put("appId", applicationIdList);
		String path = request.getSession().getServletContext().getRealPath("/");
		
		String format = null;
		if(parameters.getFormatId() == 2) {
			format = "CSV";
		} else if(parameters.getFormatId() == 3) {
			format = "PDF";
		} else {
			format = "HTML";
		}
		
		ReportFormat reportFormat = parameters.getReportFormat();
		try {
			return getReport(path, reportFormat, format, params, applicationIdList, request);
		} catch (IOException e) {
			log.error("IOException encountered while trying to generate report.", e);
			return new ReportCheckResultBean(ReportCheckResult.IO_ERROR);
		}
	}

	@SuppressWarnings("resource")
	private ReportCheckResultBean getReport(String path, ReportFormat reportFormat, String format,
			Map<String, Object> parameters, List<Integer> applicationIdList,
			HttpServletRequest request) throws IOException {

		if (reportFormat == null || reportFormat.getFileName() == null ||
				reportFormat.getFileName().trim().equals("")) {
			return null;
		}

		File file = new File(path + "jasper/" + reportFormat.getFileName());
		InputStream inputStream;
		
		if (parameters != null) {
			List<String> teamNames = applicationDao.getTeamNames(applicationIdList);
			if (teamNames != null && teamNames.size() == 1) {
				parameters.put("orgName", teamNames.get(0));
			} else if (teamNames != null) {
				parameters.put("orgName", "All");
			}
			
			if (applicationIdList.size() == 1) {
				Application app = applicationDao.retrieveById(applicationIdList.get(0));
				if (app != null) {
					parameters.put("appName", app.getName());
				}
			} else {
				parameters.put("appName", "All");
			}
			
			if (reportFormat == ReportFormat.TOP_TEN_VULNS) {
				parameters.put("vulnIds", vulnerabilityDao.getTopTenVulnTypes(applicationIdList));
			}
		}

		try {
			inputStream = new FileInputStream(file);
			
			if (reportFormat == ReportFormat.CHANNEL_COMPARISON_BY_VULN_TYPE) {
				inputStream = addCorrectColumns(inputStream, applicationIdList);
				parameters.put("badFindingIds", getFindingsToSkip(applicationIdList));
			}
			
		} catch (FileNotFoundException e) {
			log.error("Report generation failed because the file was not found.", e);
			return null;
		}

		StringBuffer report = new StringBuffer();
		JRExporter exporter;

        switch (format) {
            case "CSV":
                exporter = new JRCsvExporter();
                log.info("Starting CSV report generation.");
                break;
            case "PDF":
                exporter = new JRPdfExporter();
                log.info("Starting PDF report generation.");
                break;
            default:
                exporter = new JRHtmlExporter();
                log.info("Starting HTML report generation.");

                if (reportFormat == ReportFormat.VULNERABILITY_PROGRESS_BY_TYPE) {
                    parameters.put(JRParameter.IS_IGNORE_PAGINATION, Boolean.TRUE);
                }

                break;
        }

		if (sessionFactory != null) {
			parameters.put("HIBERNATE_SESSION", sessionFactory.getCurrentSession());
		}
		try {
			JasperDesign jasperDesign = JRXmlLoader.load(inputStream);

			JasperReport jasperReport = JasperCompileManager
					.compileReport(jasperDesign);

			JasperPrint jasperPrint;
			
			if (reportFormat == ReportFormat.TRENDING) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperScanReport(applicationIdList,scanDao));
			} else if (reportFormat == ReportFormat.SIX_MONTH_SUMMARY) {
				jasperPrint = getXMonthReport(applicationIdList, parameters, jasperReport, 6);
				if (jasperPrint == null) {
					return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
				}
			} else if (reportFormat == ReportFormat.TWELVE_MONTH_SUMMARY) {
				jasperPrint = getXMonthReport(applicationIdList, parameters, jasperReport, 12);
				if (jasperPrint == null) {
					return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
				}
			} else if (reportFormat == ReportFormat.MONTHLY_PROGRESS_REPORT) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperMonthlyScanReport(applicationIdList,scanDao));
			} else if (reportFormat == ReportFormat.VULNERABILITY_PROGRESS_BY_TYPE) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperCWEReport(applicationIdList,vulnerabilityDao));
			} else if (reportFormat == ReportFormat.CHANNEL_COMPARISON_SUMMARY) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperScannerComparisonReport(applicationIdList, vulnerabilityDao));
			} else {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters);
			}
			
			if (jasperPrint == null) {
				return null;
			}
			
			if(format.equals("PDF")) {
				byte[] pdfByteArray = JasperExportManager.exportReportToPdf(jasperPrint);
				if (pdfByteArray != null) {
					return new ReportCheckResultBean(ReportCheckResult.VALID, null, pdfByteArray);
				} else {
					return null;
				}
			}
			
			exporter.setParameter(JRExporterParameter.JASPER_PRINT, jasperPrint);
			exporter.setParameter(JRExporterParameter.OUTPUT_STRING_BUFFER,
					report);
			
			exporter.setParameter(
					JRHtmlExporterParameter.IS_OUTPUT_IMAGES_TO_DIR,
					Boolean.FALSE);
			
			String mapKey = getMapKey(reportFormat.getFileName(), applicationIdList);
			
			Map<Object, Object> imagesMap = new HashMap<>();
			request.getSession().setAttribute(mapKey, imagesMap);
            
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_MAP, imagesMap);

			exporter.setParameter(
					JRHtmlExporterParameter.IS_USING_IMAGES_TO_ALIGN,
					Boolean.TRUE);
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_URI,
					"/threadfix/jasperimage/" + mapKey + "/");

			exporter.exportReport();

		} catch (JRException ex) {
			log.error("Encountered a Jasper exception, the report was probably not exported correctly.",ex);
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}
			} catch (IOException e) {
				log.warn("Failed to close an InputStream", e);
			}
		}

		log.debug("Returning report.");
		
		return new ReportCheckResultBean(ReportCheckResult.VALID, report, null);
	}
	
	/**
	 * This method determines how the image map is stored. Down the road we may want
	 * to look at ways to use this to cache images for quick retrieval later.
	 * 
	 * @return a key for the images map
	 */
	private String getMapKey(String fileName, List<Integer> applicationIdList) {
		StringBuilder appIdString = new StringBuilder();
		
		String shorterFileName = fileName;
		if (fileName.indexOf('.') != -1) {
			shorterFileName = fileName.substring(0, fileName.indexOf('.'));
		}
		
		if (shorterFileName.length() > 10) {
			appIdString.append(shorterFileName.substring(0, 10));
		} else {
			appIdString.append(shorterFileName);
		}
		
		for (Integer id : applicationIdList) {
			appIdString.append(id);
			if (appIdString.length() > 20) {
				break;
			}
		}
		
		return appIdString.toString();
	}
	
	private JasperPrint getXMonthReport(List<Integer> applicationIdList, Map<String, Object> parameters,
			JasperReport jasperReport, int numMonths) throws JRException {
		List<List<Scan>> scanList = new ArrayList<>();
		boolean containsVulns = false;
		for (Integer id : applicationIdList) {
			scanList.add(applicationDao.retrieveById(id).getScans());
		}
		for(List<Scan> scan : scanList){
			if (!scan.isEmpty()){
				containsVulns = true;
				break;
			}
		}
		if (scanList.isEmpty() || !containsVulns ) {
			log.info("Unable to fill Jasper Report - no scans were found.");
			return null;
		} else {
			return JasperFillManager.fillReport(jasperReport, parameters,
				new JasperXMonthSummaryReport(scanList, scanDao, numMonths));
		}
	}

	private String getString(InputStream inputStream) {
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
		
		String line;
		StringBuilder buffer = new StringBuilder();
		try {
			while ((line = bufferedReader.readLine()) != null) {
				buffer.append(line);
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				log.warn("Failed to close an InputStream", e);
			}
		}
		
		return buffer.toString();
	}
	
	private InputStream getInputStream(String string) {
		if (string != null) {
			return new ByteArrayInputStream(string.getBytes());
		} else {
			return null;
		}
	}
	
	private List<ChannelType> getChannelTypesInUse(List<Integer> applicationIdList) {
		List<ChannelType> channels = channelTypeDao.retrieveAll();
		List<ChannelType> returnChannels = new ArrayList<>();
		
		for (ChannelType channel : channels) {
			if (channel.getChannels() != null && channel.getChannels().size() != 0) {
				for (ApplicationChannel applicationChannel : channel.getChannels()) {
					if (applicationChannel.getApplication() != null
							&& applicationChannel.getApplication().getId() != null
							&& applicationIdList.contains(applicationChannel.getApplication().getId())) {
						returnChannels.add(channel);
						break;
					}
				}
			}
		}

		return returnChannels;
	}
	
	// We don't want to count multiple findings that merged to one vuln from the same channel
	// it skews the numbers.
	private Set<Integer> getFindingsToSkip(List<Integer> applicationIdList) {
		Set<Integer> findingIdsToSkip = new HashSet<>();
		Set<Integer> vulnSeenChannels = new HashSet<>();
		
		// MySQL doesn't work if there are no elements here.
		findingIdsToSkip.add(0);
		
		for (Integer appId : applicationIdList) {
			Application app = applicationDao.retrieveById(appId);
			if (app == null || app.getVulnerabilities() == null) {
				continue;
			}
			
			for (Vulnerability vuln : app.getVulnerabilities()) {
				if (vuln == null || vuln.getFindings() == null) {
					continue;
				}
				vulnSeenChannels.clear();
				
				for (Finding finding : vuln.getFindings()) {
					if (finding != null && finding.getId() != null
							&& finding.getScan() != null
							&& finding.getScan().getApplicationChannel() != null
							&& finding.getScan().getApplicationChannel().getId() != null
							) {
						if (vulnSeenChannels.contains(
								finding.getScan().getApplicationChannel().getId())) {
							findingIdsToSkip.add(finding.getId());
						} else {
							vulnSeenChannels.add(
									finding.getScan().getApplicationChannel().getId());
						}
					}
				}
			}
		}
		
		return findingIdsToSkip;
	}
	
	private InputStream addCorrectColumns(InputStream inputStream, List<Integer> applicationIdList) {
		log.debug("Adding the correct headers to the CWE Channel report Input Stream.");
		
		String string = getString(inputStream);
		
		List<ChannelType> channelTypeList = getChannelTypesInUse(applicationIdList);
		
		Integer base = 470, increment = 140, count = 0;
		int amountToAdd = increment * channelTypeList.size();
		String width = ((Integer) (base + amountToAdd)).toString();
		
		string = string.replace("<reportElement x=\"0\" y=\"113\" width=\"772\" height=\"1\"/>",
					"<reportElement x=\"0\" y=\"113\" width=\"" + width + "\" height=\"1\"/>");
		
		string = string.replace("<reportElement x=\"346\" y=\"0\" width=\"200\" height=\"40\"/>",
				"<reportElement x=\"0\" y=\"0\" width=\"" + width + "\" height=\"40\"/>");
		
		string = string.replace("<reportElement x=\"0\" y=\"40\" width=\"800\" height=\"20\"/>",
				"<reportElement x=\"0\" y=\"40\" width=\"" + width + "\" height=\"20\"/>");
		
		string = string.replace("<reportElement x=\"0\" y=\"60\" width=\"800\" height=\"20\"/>",
				"<reportElement x=\"0\" y=\"60\" width=\"" + width + "\" height=\"20\"/>");
		
		//<reportElement x="0" y="45" width="800" height="20"/>
		
		string = string.replace("pageWidth=\"792\"", "pageWidth=\"" + width + "\"");
		
		for (ChannelType channelType : channelTypeList) {
			if (channelType == null || channelType.getId() == null) {
				continue;
			}
			String id = channelType.getId().toString();
			String location = String.valueOf(base + count*increment);
			
			String sumLine = ", SUM(CASE WHEN scan.applicationChannel.channelType.id = "
				+ id + " AND id NOT IN ( \\$P\\{badFindingIds\\} ) THEN 1 ELSE 0 END) as count_" + id + "\n";
			string = string.replaceFirst("FROM Finding", sumLine + "FROM Finding");
			
			String fieldTag = "<field name=\"count_" + id + "\" class=\"java.lang.Long\"/>\n";
			string = string.replaceFirst("<background>", fieldTag + "<background>");
			
			String textFieldTag = "\n<textField>\n"
				+ "<reportElement x=\"" + location + "\" y=\"0\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "\t<textElement textAlignment=\"Center\" verticalAlignment=\"Middle\">\n"
				+ "\t\t<font size=\"12\" pdfFontName=\"Helvetica-Bold\"/>\n"
				+ "\t</textElement>\n"
				+ "\t<textFieldExpression class=\"java.lang.Long\"><![CDATA[\\$F{count_"
				+ id
				+ "}]]></textFieldExpression>\n"
				+ "</textField>";
			string = string.replaceFirst("</band>	</detail", textFieldTag + "</band>	</detail");
			
			String headerText = "<staticText>\n"
				+ "<reportElement x=\"" + location + "\" y=\"90\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "<textElement textAlignment=\"Center\" verticalAlignment=\"Middle\">\n"
				+ "\t<font size=\"12\" pdfFontName=\"Helvetica-Bold\"/>\n"
				+ "</textElement>\n"
				+ "<text><![CDATA[" + channelType.getName() + "]]></text>\n"
				+ "</staticText>\n";
			string = string.replaceFirst("<line>", headerText + "<line>");
			
			count += 1;
		}
		
		return getInputStream(string);
	}
	
	private List<Integer> getApplicationIdList(ReportParameters reportParameters) {
		List<Integer> applicationIdList = new ArrayList<>();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

		if (reportParameters.getOrganizationId() < 0) {
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList;
				
				if (PermissionUtils.hasGlobalReadAccess()) {
					appList = applicationDao.retrieveAllActive();
				} else if (teamIds == null || teamIds.size() == 0) {
					appList = new ArrayList<>();
				} else {
					appList = applicationDao.retrieveAllActiveFilter(teamIds);
				}
				
				for (Application app : appList) {
					applicationIdList.add(app.getId());
				}
				
				Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
				if (appIds != null && !appIds.isEmpty()) {
					applicationIdList.addAll(appIds);
				}
			} else {
				applicationIdList.add(reportParameters.getApplicationId());
			}
		} else if (PermissionUtils.hasGlobalPermission(Permission.READ_ACCESS) ||
				teamIds.contains(reportParameters.getOrganizationId())) {
			Organization org = organizationDao.retrieveById(reportParameters.getOrganizationId());
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList = org.getActiveApplications();
				for (Application app : appList) {
					if (app.isActive()) {
						applicationIdList.add(app.getId());
					}
				}
			} else {
				applicationIdList.add(reportParameters.getApplicationId());
			}
		}
		
		return applicationIdList;
	}
	
	// TODO rethink some of this - it's a little slow at a few hundred vulns.
	// The emphasis on genericism through the design makes it harder to pull channel-specific info from vulns.
	@Override
	public String scannerComparisonByVulnerability(Model model, ReportParameters reportParameters) {
		
		List<List<String>> tableListOfLists = new ArrayList<>();
		List<String> headerList = new ArrayList<>(); // this facilitates headers
		List<Application> applicationList = new ArrayList<>();
		
		// this map is used to insert the value into the correct space.
		Map<Integer, Integer> channelIdToTablePositionMap = new HashMap<>();
		
		// positions 0, 1, and 2 are the generic name, path, and parameter of the vulnerability.
		// 3 is open status
		// This also represents the number of headers.
		int columnCount = 4;
		
		List<Integer> applicationIdList = getApplicationIdList(reportParameters);

		for (int id : applicationIdList) {
			Application application = applicationDao.retrieveById(id);
			
			if (application == null || application.getChannelList() == null
					|| application.getVulnerabilities() == null) {
				continue;
			}
			applicationList.add(application);
						
			for (ApplicationChannel channel : application.getChannelList()) {
				if (channel == null || channel.getScanCounter() == null
						|| channel.getChannelType() == null
						|| channel.getChannelType().getId() == null
						|| channel.getChannelType().getName() == null) {
					continue;
				}
				
				int channelTypeId = channel.getChannelType().getId();
				
				if (!channelIdToTablePositionMap.containsKey(channelTypeId)) {
					headerList.add(channel.getChannelType().getName());
					channelIdToTablePositionMap.put(channelTypeId, columnCount++);
				}
			}
		}
		
		for (Application application : applicationList) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || vuln.getFindings() == null
						|| !vuln.isActive() && !vuln.getHidden() && !vuln.getIsFalsePositive()) {
					continue;
				}
				
				List<String> tempList = new ArrayList<>(columnCount);
				
				String falsePositive = vuln.getIsFalsePositive() ? "FP" : "OPEN";
				if (vuln.getHidden()) {
					falsePositive = "HIDDEN";
				}

				tempList.addAll(Arrays.asList(vuln.getGenericVulnerability().getName(),
											  vuln.getSurfaceLocation().getPath(),
											  vuln.getSurfaceLocation().getParameter(),
											  falsePositive));
				
				for (int i = 4; i < columnCount; i++) {
					tempList.add(" ");
				}
				
				// For each finding, if the path to the channel type ID is not null, put an X in the table
				for (Finding finding : vuln.getFindings()) {
					if (finding != null && finding.getScan() != null
							&& finding.getScan().getApplicationChannel() != null
							&& finding.getScan().getApplicationChannel().getChannelType() != null
							&& finding.getScan().getApplicationChannel().getChannelType().getId() != null)
					{
						Integer tablePosition = channelIdToTablePositionMap.get(
								finding.getScan().getApplicationChannel().getChannelType().getId());
						if (tablePosition != null) {
							tempList.set(tablePosition, "X");
						}
					}
				}
				
				tableListOfLists.add(tempList);
			}
		}
		
		model.addAttribute("headerList", headerList);
		model.addAttribute("listOfLists", tableListOfLists);
		model.addAttribute("columnCount", columnCount);
		model.addAttribute("contentPage", "reports/scannerComparisonByVulnerability.jsp");
				
		return "ajaxSuccessHarness";
	}

	@Override
	public String vulnerabilityList(Model model,
			ReportParameters reportParameters) {
		List<Integer> applicationIdList = getApplicationIdList(reportParameters);
		
		model.addAttribute("listOfLists", getListofRowParams(applicationIdList));
		model.addAttribute("contentPage", "reports/vulnerabilityList.jsp");
				
		return "ajaxSuccessHarness";
	}
	
	private List<List<String>> getListofRowParams(List<Integer> applicationIdList) {
		List<List<String>> rowParamsList = new ArrayList<>();
		List<Application> applicationList = new ArrayList<>();

		for (int id : applicationIdList) {
			Application application = applicationDao.retrieveById(id);
			
			if (application == null || application.getChannelList() == null 
					|| application.getVulnerabilities() == null)
				continue;
			applicationList.add(application);
		}
		
		SimpleDateFormat formatter=new SimpleDateFormat("dd-MMM-yyyy");
		
		for (Application application : applicationList) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || (!vuln.isActive() && !vuln.getIsFalsePositive())) {
					continue;
				}
				String openedDate = formatter.format(vuln.getOpenTime().getTime());
				// Orders of positions: CWE ID, CWE Name, Path, Parameter, Severity, Open Date, Defect ID
				rowParamsList.add(Arrays.asList(vuln.getGenericVulnerability().getId().toString(),
						vuln.getGenericVulnerability().getName(),
						vuln.getSurfaceLocation().getPath(), 
						vuln.getSurfaceLocation().getParameter(),
						vuln.getGenericSeverity().getName(),
						openedDate,
						(vuln.getDefect() == null) ? "" : vuln.getDefect().getId().toString()));
			}
		}
		return rowParamsList;
	}
	
	private StringBuffer getDataVulnListReport(List<List<String>> rowParamsList, List<Integer> applicationIdList) {
		StringBuffer data = new StringBuffer();
		data.append("Vulnerability List \n");

		List<String> teamNames = applicationDao.getTeamNames(applicationIdList);
		String teamName = (teamNames != null && teamNames.size() == 1) ? teamNames.get(0) : "All";
		data.append("Team: ").append(teamName).append(" \n");
		String appName = ""; 
		if (applicationIdList.size() == 1) {
			Application app = applicationDao.retrieveById(applicationIdList.get(0));
			if (app != null) {
				appName = app.getName();
			}
		} else {
			appName = "All";
		}
		data.append("Application: ").append(appName).append(" \n \n");
		data.append("CWE ID, CWE Name, Path, Parameter, Severity, Open Date, Defect ID \n");
		for (List<String> row: rowParamsList) {
			for (int i=0;i<row.size();i++) {
				String str = "";
				if (row.get(i) != null) str = row.get(i).replace(",", " ");
				if (i<row.size()-1)
					data.append(str).append(",");
				else data.append(str).append(" \n");
			}
		}
		return data;
	}

}
