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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.jasperreports.engine.JRException;
import net.sf.jasperreports.engine.JRExporter;
import net.sf.jasperreports.engine.JRExporterParameter;
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
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.PermissionUtils;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;

/**
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
	 * @param organizationService
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
			HttpServletRequest request, HttpServletResponse response) {
		if (parameters.getReportFormat() == ReportFormat.BAD_FORMAT) {
			return new ReportCheckResultBean(ReportCheckResult.BAD_REPORT_TYPE, null);
		}
		
		List<Integer> applicationIdList = getApplicationIdList(parameters);
	
		if (applicationIdList == null || applicationIdList.isEmpty()) {
			return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS, null);
		}
		
		log.info("About to generate report for " + applicationIdList.size() + " applications.");
	
		Map<String, Object> params = new HashMap<String, Object>();
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
		
		String reportFile = parameters.getReportFormat().getFileName();
		try {
			StringBuffer report = getReport(path, reportFile, format, params, applicationIdList, response);
			return new ReportCheckResultBean(ReportCheckResult.VALID, report);
		} catch (IOException e) {
			log.error("IOException encountered while trying to generate report.", e);
			return new ReportCheckResultBean(ReportCheckResult.IO_ERROR, null);
		}
	}

	@SuppressWarnings("resource")
	private StringBuffer getReport(String path, String fileName, String format,
			Map<String, Object> parameters, List<Integer> applicationIdList, 
			HttpServletResponse response) throws IOException {

		if (fileName == null || fileName.trim().equals(""))
			return null;

		File file = new File(path + "jasper/" + fileName);
		InputStream inputStream = null;
		
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
		}

		try {
			inputStream = new FileInputStream(file);
			
			if (fileName.contains("cweChannel")) {
				inputStream = addCorrectColumns(inputStream, applicationIdList);
				parameters.put("badFindingIds", getFindingsToSkip(applicationIdList));
			}
			
		} catch (FileNotFoundException e) {
			log.error("Report generation failed because the file was not found.", e);
			return null;
		}

		StringBuffer report = new StringBuffer();
		JRExporter exporter = null;
		
		if(format.equals("CSV")) {
			exporter = new JRCsvExporter();
			log.info("Starting CSV report generation.");
		} else if(format.equals("PDF")) {
			exporter = new JRPdfExporter();
			log.info("Starting PDF report generation.");
		} else {
			exporter = new JRHtmlExporter();
			log.info("Starting HTML report generation.");
		}

		parameters.put("HIBERNATE_SESSION", sessionFactory.getCurrentSession());
		try {
			JasperDesign jasperDesign = JRXmlLoader.load(inputStream);

			JasperReport jasperReport = JasperCompileManager
					.compileReport(jasperDesign);

			JasperPrint jasperPrint = null;
			
			if (fileName.equals("trending.jrxml")) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperScanReport(applicationIdList,scanDao));
			} else if (fileName.equals("monthlyBarChart.jrxml")) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperMonthlyScanReport(applicationIdList,scanDao));
			} else if (fileName.equals("cwe.jrxml")) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperCWEReport(applicationIdList,vulnerabilityDao));
			} else if (fileName.equals("scannerComparison.jrxml")) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperScannerComparisonReport(applicationIdList, vulnerabilityDao));
			} else {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters);
			}
			
			if(format.equals("PDF")) {
				response.setContentType( "application/pdf" );
				response.setHeader("Content-Disposition", "attachment; filename=\"threadfix_report_" + applicationIdList
						+ ".pdf\"");

				ServletOutputStream out = response.getOutputStream();
								
				byte[] pdfByteArray = JasperExportManager.exportReportToPdf(jasperPrint);
				
				out.write(pdfByteArray, 0, pdfByteArray.length);
				out.flush();
				out.close();
				return null;
			}
			
			exporter.setParameter(JRExporterParameter.JASPER_PRINT, jasperPrint);
			exporter.setParameter(JRExporterParameter.OUTPUT_STRING_BUFFER,
					report);
			
			StringBuffer appIdString = new StringBuffer();
			appIdString.append(fileName.charAt(0));
			for (Integer id : applicationIdList) {
				appIdString.append(id);
			}

			exporter.setParameter(
					JRHtmlExporterParameter.IS_OUTPUT_IMAGES_TO_DIR,
					Boolean.TRUE);
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_DIR_NAME, path
					+ "jasper/" + appIdString);

			exporter.setParameter(
					JRHtmlExporterParameter.IS_USING_IMAGES_TO_ALIGN,
					Boolean.TRUE);
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_URI,
					"jasper/" + appIdString + "/");

			exporter.exportReport();

		} catch (JRException ex) {
			log.error("Encountered a Jasper exception, the report was probably not exported correctly.",ex);
		} finally {
			try {
				if (inputStream != null)
					inputStream.close();
			} catch (IOException e) {
				log.warn("Failed to close an InputStream", e);
			}
		}

		log.debug("Returning report.");
		
		return report;
	}

	private String getString(InputStream inputStream) {
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
		
		String line = null;
		StringBuffer buffer = new StringBuffer();
		try {
			while ((line = bufferedReader.readLine()) != null)
				buffer.append(line);
			
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
		if (string != null)
			return new ByteArrayInputStream(string.getBytes());
		else
			return null;
	}
	
	private List<ChannelType> getChannelTypesInUse(List<Integer> applicationIdList) {
		List<ChannelType> channels = channelTypeDao.retrieveAll();
		List<ChannelType> returnChannels = new ArrayList<ChannelType>();
		
		for (ChannelType channel : channels)
			if (channel.getChannels() != null && channel.getChannels().size() != 0)
				for (ApplicationChannel applicationChannel : channel.getChannels())
					if (applicationChannel.getApplication() != null 
							&& applicationChannel.getApplication().getId() != null
							&& applicationIdList.contains(applicationChannel.getApplication().getId())) {
						returnChannels.add(channel);
						break;
					}

		return returnChannels;
	}
	
	// We don't want to count multiple findings that merged to one vuln from the same channel
	// it skews the numbers.
	private Set<Integer> getFindingsToSkip(List<Integer> applicationIdList) {
		Set<Integer> findingIdsToSkip = new HashSet<Integer>();
		Set<Integer> vulnSeenChannels = new HashSet<Integer>();
		
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
		int amountToAdd = (increment * channelTypeList.size());
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
			if (channelType == null || channelType.getId() == null)
				continue;
			String id = channelType.getId().toString();
			String location = String.valueOf(base + (count*increment));
			
			String sumLine = ", SUM(CASE WHEN scan.applicationChannel.channelType.id = " 
				+ id + " AND id NOT IN ( \\$P\\{badFindingIds\\} ) THEN 1 ELSE 0 END) as count_" + id + "\n";
			string = string.replaceFirst("FROM Finding", sumLine + "FROM Finding");
			
			String fieldTag = "<field name=\"count_" + id + "\" class=\"java.lang.Long\"/>\n";
			string = string.replaceFirst("<background>", fieldTag + "<background>");
			
			String textFieldTag = "\n<textField>\n"
				+ "<reportElement x=\"" + location + "\" y=\"0\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "\t<textElement verticalAlignment=\"Middle\">\n"
				+ "\t\t<font size=\"12\" pdfFontName=\"Helvetica-Bold\"/>\n"
				+ "\t</textElement>\n"
				+ "\t<textFieldExpression class=\"java.lang.Long\"><![CDATA[\\$F{count_"
				+ id
				+ "}]]></textFieldExpression>\n"
				+ "</textField>";
			string = string.replaceFirst("</band>	</detail", textFieldTag + "</band>	</detail");
			
			String headerText = "<staticText>\n"
				+ "<reportElement x=\"" + location + "\" y=\"90\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "<textElement verticalAlignment=\"Middle\">\n"
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
		List<Integer> applicationIdList = new ArrayList<Integer>();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

		if (reportParameters.getOrganizationId() < 0) {
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList = null;
				
				if (PermissionUtils.hasGlobalReadAccess()) {
					appList = applicationDao.retrieveAllActive();
				} else if (teamIds == null || teamIds.size() == 0) {
					appList = new ArrayList<Application>();
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
		
		List<List<String>> tableListOfLists = new ArrayList<List<String>>();
		List<String> headerList = new ArrayList<String>(); // this facilitates headers
		List<Application> applicationList = new ArrayList<Application>();
		
		// this map is used to insert the value into the correct space.
		Map<Integer, Integer> channelIdToTablePositionMap = new HashMap<Integer, Integer>();
		
		// positions 0, 1, and 2 are the generic name, path, and parameter of the vulnerability.
		// 3 is open status
		// This also represents the number of headers.
		int columnCount = 4;
		
		List<Integer> applicationIdList = getApplicationIdList(reportParameters);

		for (int id : applicationIdList) {
			Application application = applicationDao.retrieveById(id);
			
			if (application == null || application.getChannelList() == null 
					|| application.getVulnerabilities() == null)
				continue;
			applicationList.add(application);
						
			for (ApplicationChannel channel : application.getChannelList()) {
				if (channel == null || channel.getScanCounter() == null
						|| channel.getChannelType() == null 
						|| channel.getChannelType().getId() == null
						|| channel.getChannelType().getName() == null)
					continue;
				
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
						|| (!vuln.isActive() && !vuln.getIsFalsePositive())) {
					continue;
				}
				
				List<String> tempList = new ArrayList<String>(columnCount);
				
				String falsePositive = vuln.getIsFalsePositive() ? "FP" : "OPEN";

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
}
