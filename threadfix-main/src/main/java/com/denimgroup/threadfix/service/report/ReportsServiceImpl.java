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
package com.denimgroup.threadfix.service.report;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;
import net.sf.jasperreports.engine.*;
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

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * @author mcollins
 * @author drivera
 * 
 */
@Service
public class ReportsServiceImpl implements ReportsService {

    private final SanitizedLogger log = new SanitizedLogger(ReportsServiceImpl.class);

    @Autowired
    private SessionFactory    sessionFactory    = null;
    @Autowired
    private ChannelTypeDao    channelTypeDao    = null;
    @Autowired
    private ScanDao           scanDao           = null;
    @Autowired
    private VulnerabilityDao  vulnerabilityDao  = null;
    @Autowired
    private GenericVulnerabilityDao  genericVulnerabilityDao  = null;
    @Autowired
    private OrganizationDao   organizationDao   = null;
    @Autowired
    private ApplicationDao    applicationDao    = null;
    @Autowired(required = false)
    @Nullable
    private PermissionService permissionService = null;
    @Autowired
    private FilterJsonBlobDao filterJsonBlobDao = null;


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

        if (parameters.getReportFormat() == ReportFormat.TOP_TWENTY_APPS) {
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
        if (parameters.getFormatId() == 2) {
            format = "CSV";
        } else if (parameters.getFormatId() == 3) {
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
        } finally {
            log.info("Finished generating report.");
        }
    }

    @Override
    public ReportCheckResultBean generateDashboardReport(ReportParameters parameters, HttpServletRequest request) {

        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList == null || applicationIdList.isEmpty()) {
            return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
        }

        ReportCheckResultBean report = null;

        if (parameters.getReportFormat() == ReportFormat.TOP_TEN_APPS) {
            applicationIdList = applicationDao.getTopXVulnerableAppsFromList(10, applicationIdList);
            report = getTopAppsReportD3(applicationIdList);
        }
        if (parameters.getReportFormat() == ReportFormat.POINT_IN_TIME_GRAPH) {
            report = getPointInTimeD3(applicationIdList, parameters.getOrganizationId());
        }

        if (parameters.getReportFormat() == ReportFormat.TOP_TEN_VULNS) {
            List<Integer> vulnIds = vulnerabilityDao.getTopTenVulnTypes(applicationIdList);
            report = getTopVulnsReportD3(applicationIdList, vulnIds);
        }

        if (parameters.getReportFormat() == ReportFormat.TRENDING) {
            JasperScanReport reportExporter = new JasperScanReport(applicationIdList, scanDao, filterJsonBlobDao.getDefaultFilter());
            report = new ReportCheckResultBean(ReportCheckResult.VALID, null, null, reportExporter.buildReportList());
        }

        if (report == null || report.getReportList() == null || report.getReportList().size()==0)
            return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);

        return report;
    }

    @Override
    public Map<String, Object> generateTrendingReport(ReportParameters parameters, HttpServletRequest request) {

        Map<String, Object> map = newMap();

        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList == null || applicationIdList.isEmpty()) {
            log.info("Unable to fill Report - no applications were found.");
            return map;
        }

        List<Scan> scanList = scanDao.retrieveByApplicationIdList(applicationIdList);
        if (scanList == null || scanList.isEmpty()) {
            log.info("Unable to fill Report - no scans were found.");
            return map;
        }
        map.put("scanList", scanList);

        return map;
    }

    @Override
    public Map<String, Object> generateSnapshotReport(ReportParameters parameters, HttpServletRequest request) {
        Map<String, Object> map = newMap();
        List<Integer> applicationIdList = getApplicationIdList(parameters);
        if (applicationIdList.isEmpty()) {
            log.info("No applications found.");
            return map;
        }
        map.put("vulnList", vulnerabilityDao.retrieveMapByApplicationIdList(applicationIdList));

        List<Integer> top20Apps = applicationDao.getTopXVulnerableAppsFromList(20, applicationIdList);
        map.put("appList", getTopAppsListInfo(top20Apps));

        return map;
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
		
        updateParameters(applicationIdList, parameters);

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
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, new JasperScanReport(applicationIdList, scanDao, null));
			} else if (reportFormat == ReportFormat.TWELVE_MONTH_SUMMARY) {
				jasperPrint = getXMonthReport(applicationIdList, parameters, jasperReport, 12);
				if (jasperPrint == null) {
					return new ReportCheckResultBean(ReportCheckResult.NO_APPLICATIONS);
				}
			} else if (reportFormat == ReportFormat.MONTHLY_PROGRESS_REPORT) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters,
                        new JasperMonthlyScanReport(applicationIdList, scanDao));
			} else if (reportFormat == ReportFormat.VULNERABILITY_PROGRESS_BY_TYPE) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters,
                        new JasperCWEReport(applicationIdList,vulnerabilityDao));
			} else if (reportFormat == ReportFormat.CHANNEL_COMPARISON_SUMMARY) {
				jasperPrint = JasperFillManager.fillReport(jasperReport, parameters,
                        new JasperScannerComparisonReport(applicationIdList, vulnerabilityDao));
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
			
			String mapKey = getMapKey(reportFormat.ordinal(), applicationIdList);
			
			Map<Object, Object> imagesMap = new HashMap<>();
			request.getSession().setAttribute(mapKey, imagesMap);
            
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_MAP, imagesMap);

			exporter.setParameter(
					JRHtmlExporterParameter.IS_USING_IMAGES_TO_ALIGN,
					Boolean.TRUE);

            String imagesPath = request.getContextPath() + "/jasperimage/" + mapKey + "/";

			exporter.setParameter(JRHtmlExporterParameter.IMAGES_URI,
                    imagesPath);

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

    private void updateParameters(List<Integer> applicationIdList, Map<String, Object> parameters) {

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
    }

    private ReportCheckResultBean getTopVulnsReportD3(List<Integer> applicationIdList, List<Integer> vulnIds) {

        List<Object[]> vulns = vulnerabilityDao.getTopVulnsInfo(applicationIdList, vulnIds);
        List<Map<String, Object>> resultList = list();
        Application application = applicationDao.retrieveById(applicationIdList.get(0));
        for (Object[] objects: vulns) {
            if (objects != null && objects.length == 2) {

                if (!(objects[0] instanceof Integer)) continue;
                GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveById((Integer) objects[0]);
                Map<String, Object> hash = newMap();
                hash.put("count", objects[1]);
                hash.put("title", "CWE-" + genericVulnerability.getDisplayId());
                hash.put("name", genericVulnerability.getName());
                hash.put("cweId", genericVulnerability.getId());
                hash.put("displayId", genericVulnerability.getDisplayId());
                hash.put("appId", applicationIdList.get(0));
                if (application != null){
                    hash.put("appName", application.getName());
                    hash.put("teamId", application.getOrganization().getId());
                    hash.put("teamName", application.getOrganization().getName());
                }

                resultList.add(hash);
            }
        }

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no vulns were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
        }

    }

    /**
	 * This method determines how the image map is stored. Down the road we may want
	 * to look at ways to use this to cache images for quick retrieval later.
	 * 
	 * @return a key for the images map
	 */
	private String getMapKey(int ordinal, List<Integer> applicationIdList) {
		StringBuilder appIdString = new StringBuilder();

        appIdString.append(ordinal);

        appIdString.append(new Date().getTime());

		for (Integer id : applicationIdList) {
            appIdString.append(id);
			if (appIdString.length() > 30) {
				break;
			}
		}

		return appIdString.toString();
	}
	
	private JasperPrint getXMonthReport(List<Integer> applicationIdList, Map<String, Object> parameters,
			JasperReport jasperReport, int numMonths) throws JRException {
		List<List<Scan>> scanList = list();
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
//			return JasperFillManager.fillReport(jasperReport, parameters,
//				new XMonthSummaryReport(scanList, scanDao, numMonths));
            return null;
		}
	}

    private ReportCheckResultBean getTopAppsReportD3(List<Integer> applicationIdList) {

        List<Map<String, Object>> resultList = getTopAppsListInfo(applicationIdList);

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no apps were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
        }
    }

    private List<Map<String, Object>> getTopAppsListInfo(List<Integer> applicationIdList) {
        List<Application> apps = applicationDao.getTopAppsFromList(applicationIdList);
        List<Map<String, Object>> resultList = list();
        for (Application app: apps) {
            Map<String, Object> hash = newMap();
            hash.put("Critical", app.getCriticalVulnCount());
            hash.put("High", app.getHighVulnCount());
            hash.put("Medium", app.getMediumVulnCount());
            hash.put("Low", app.getLowVulnCount());
            hash.put("Info", app.getInfoVulnCount());
            hash.put("appId", app.getId());
            hash.put("appName", app.getName());
            hash.put("teamId", app.getOrganization().getId());
            hash.put("teamName", app.getOrganization().getName());

            hash.put("title", app.getOrganization().getName() + "/" + app.getName());
            resultList.add(hash);
        }

        return resultList;
    }

    private ReportCheckResultBean getPointInTimeD3(List<Integer> applicationIdList, int teamId) {

        List<Object[]> objects = applicationDao.getPointInTime(applicationIdList);
        Organization team = organizationDao.retrieveById(teamId);
        List<Map<String, Object>> resultList = list();
        for (Object[] infoArr: objects) {
            Map<String, Object> hash = newMap();

            if (infoArr != null && infoArr.length >= 5) {
                hash.put("Critical", infoArr[4]);
                hash.put("High", infoArr[3]);
                hash.put("Medium", infoArr[2]);
                hash.put("Low", infoArr[1]);
                hash.put("Info", infoArr[0]);
                hash.put("teamId", teamId);
                if (team != null)
                    hash.put("teamName", team.getName());
            }
            resultList.add(hash);
        }

        if (resultList.size() == 0 ) {
            log.info("Unable to fill Report - no vulns were found.");
            return null;
        } else {
            return new ReportCheckResultBean(ReportCheckResult.VALID, null, null, resultList);
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
		List<ChannelType> returnChannels = list();
		
		for (ChannelType channel : channels) {
			if (channel.getChannels() != null && channel.getChannels().size() != 0) {
				for (ApplicationChannel applicationChannel : channel.getChannels()) {
					if (applicationChannel.getApplication() != null
							&& applicationChannel.getApplication().getId() != null
                            && (applicationChannel.getScanList() != null && applicationChannel.getScanList().size()>0)
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
		List<Integer> applicationIdList = list();
		Set<Integer> teamIds = null;
        if (permissionService == null) {
            teamIds = new HashSet<>();
            List<Organization> organizations = organizationDao.retrieveAllActive();

            if (organizations != null) {
                for (Organization organization : organizations) {
                    teamIds.add(organization.getId());
                }
            }
        } else {
            teamIds = permissionService.getAuthenticatedTeamIds();
        }

		if (reportParameters.getOrganizationId() < 0) {
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList;
				
				if (PermissionUtils.hasGlobalReadAccess()) {
					appList = applicationDao.retrieveAllActive();
				} else if (teamIds == null || teamIds.size() == 0) {
					appList = list();
				} else {
					appList = applicationDao.retrieveAllActiveFilter(teamIds);
				}
				
				for (Application app : appList) {
					applicationIdList.add(app.getId());
				}
				
				Set<Integer> appIds = PermissionUtils.getAuthenticatedAppIds();
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
    public Map<String, Object> scannerComparisonByVulnerability(Model model, ReportParameters reportParameters) {
		
		List<List<String>> tableListOfLists = list();
		List<String> headerList = list(); // this facilitates headers
		List<Application> applicationList = list();
		
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
                        || channel.getScanList() == null
                        || channel.getScanList().size() == 0
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

        Map<String, Object> map = new HashMap<>();

        map.put("headerList", headerList);
        map.put("listOfLists", tableListOfLists);
        map.put("columnCount", columnCount);
        map.put("reportHTML", "");

        return map;
	}

	@Override
	public Map<String, Object> vulnerabilityList(Model model,
			ReportParameters reportParameters) {
		List<Integer> applicationIdList = getApplicationIdList(reportParameters);
        Map<String, Object> map = new HashMap<>();
        map.put("listOfLists", getListofRowParams(applicationIdList));
        return map;
	}

    @Override
    public String getExportFileName(ReportParameters reportParameters) {
        String reportFormat = reportParameters.getReportFormat().getFileName();
        int index = reportFormat.indexOf(".");
        if (index > 0)
            reportFormat = reportFormat.substring(0,index);

        String teamName = null;
        if (reportParameters.getOrganizationId() < 0)
            teamName = "All";
        else {
            Organization org = organizationDao.retrieveById(reportParameters.getOrganizationId());
            if (org != null)
                teamName = org.getName();
        }

        String appName = null;
        if (reportParameters.getApplicationId() < 0)
            appName = "All";
        else {
            Application app = applicationDao.retrieveById(reportParameters.getApplicationId());
            if (app != null)
                appName = app.getName();
        }

        return reportFormat + "_" + teamName + "_" + appName;
    }

    @Override
    public ReportCheckResultBean generateSearchReport(List<Vulnerability> vulnerabilityList) {
        StringBuffer dataExport = getDataVulnListReport(getVulnListInfo(vulnerabilityList), null);
        return new ReportCheckResultBean(ReportCheckResult.VALID, dataExport, null);
    }

    private List<List<String>> getListofRowParams(List<Integer> applicationIdList) {
		List<List<String>> rowParamsList = list();
		List<Application> applicationList = list();

		for (int id : applicationIdList) {
			Application application = applicationDao.retrieveById(id);
			
			if (application == null || application.getChannelList() == null 
					|| application.getVulnerabilities() == null)
				continue;
			applicationList.add(application);
		}
		
		SimpleDateFormat formatter=new SimpleDateFormat("yyyy-MM-dd");
		
		for (Application application : applicationList) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || (!vuln.isActive() && !vuln.getIsFalsePositive())) {
					continue;
				}

				String openedDate = formatter.format(vuln.getOpenTime().getTime());
				// Orders of positions: CWE ID, CWE Name, Path, Parameter, Severity, Open Date, Defect ID
				rowParamsList.add(list(vuln.getGenericVulnerability().getId().toString(),
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

    private List<List<String>> getVulnListInfo(List<Vulnerability> vulnerabilityList) {
        List<List<String>> rowParamsList = list();
        SimpleDateFormat formatter=new SimpleDateFormat("yyyy-MM-dd");
        for (Vulnerability vuln : vulnerabilityList) {
            if (vuln == null || (!vuln.isActive() && !vuln.getIsFalsePositive())) {
                continue;
            }

            String openedDate = formatter.format(vuln.getOpenTime().getTime());
            // Order of fields: CWE ID, CWE Name, Path, Parameter, Severity, Open Date, Defect ID, Application, Team, Payload, Attack surface path
            rowParamsList.add(list(
                    vuln.getGenericVulnerability().getId().toString(),
                    vuln.getGenericVulnerability().getName(),
                    vuln.getSurfaceLocation().getPath(),
                    vuln.getSurfaceLocation().getParameter(),
                    vuln.getGenericSeverity().getName(),
                    openedDate,
                    (vuln.getDefect() == null) ? "" : vuln.getDefect().getNativeId(),
                    vuln.getApplication().getName(),
                    vuln.getApplication().getOrganization().getName(),
                    vuln.getSurfaceLocation().getQuery() == null ? "" : vuln.getSurfaceLocation().getQuery(),
                    vuln.getSurfaceLocation().getUrl() == null ? "" : vuln.getSurfaceLocation().getUrl().toString()
            ));
        }
        return rowParamsList;
    }
	
	private StringBuffer getDataVulnListReport(List<List<String>> rowParamsList, List<Integer> applicationIdList) {
		StringBuffer data = new StringBuffer();
		data.append("Vulnerability List \n\n");

        if (applicationIdList != null) {

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
        }

		data.append("CWE ID, CWE Name, Path, Parameter, Severity, Open Date, Defect ID, Application Name, Team Name, Payload, Attack Surface Path \n");
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
