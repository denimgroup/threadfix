////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import java.util.List;
import java.util.Map;

import javax.servlet.ServletOutputStream;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;

/**
 * @author drivera
 * 
 */
@Service
public class ReportsServiceImpl implements ReportsService {
	private final Log log = LogFactory.getLog(ReportsServiceImpl.class);
	
	private SessionFactory sessionFactory = null;
	private ChannelTypeDao channelTypeDao = null;
	private ScanDao scanDao = null;
	private VulnerabilityDao vulnerabilityDao = null;

	/**
	 * @param sessionFactory
	 * @param organizationService
	 */
	@Autowired
	public ReportsServiceImpl(SessionFactory sessionFactory, ChannelTypeDao channelTypeDao,
			ScanDao scanDao, VulnerabilityDao vulnerabilityDao) {
		this.sessionFactory = sessionFactory;
		this.channelTypeDao = channelTypeDao;
		this.scanDao = scanDao;
		this.vulnerabilityDao = vulnerabilityDao;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.report.ReportsService#getReport(java
	 * .lang.String, java.lang.String, net.sf.jasperreports.engine.JRDataSource,
	 * java.util.Map)
	 */
	@Override
	public StringBuffer getReport(String path, String fileName, String format,
			Map<String, Object> parameters, List<Integer> applicationIdList, HttpServletResponse response) throws IOException{

		if (fileName == null || fileName.trim().equals(""))
			return null;

		File file = new File(path + "jasper/" + fileName);
		InputStream inputStream = null;

		try {
			inputStream = new FileInputStream(file);
			
			if (fileName.contains("cweChannel")) {
				inputStream = addCorrectColumns(inputStream, applicationIdList);
			}
			
		} catch (FileNotFoundException e) {
			log.error("Report generation failed because the file was not found.");
			e.printStackTrace();
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
				response.setHeader("Content-Disposition", "attachment; filename=\"report_csv_" + applicationIdList
						+ ".pdf\"");

				ServletOutputStream out = response.getOutputStream();

				byte[] pdfByteArray = JasperExportManager.exportReportToPdf(jasperPrint);
				
				out.write(pdfByteArray, 0, pdfByteArray.length);
				out.flush();
				out.close();
			}
			
			exporter.setParameter(JRExporterParameter.JASPER_PRINT, jasperPrint);
			exporter.setParameter(JRExporterParameter.OUTPUT_STRING_BUFFER,
					report);

			exporter.setParameter(
					JRHtmlExporterParameter.IS_OUTPUT_IMAGES_TO_DIR,
					Boolean.TRUE);
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_DIR_NAME, path
					+ "jasper/images/");

			exporter.setParameter(
					JRHtmlExporterParameter.IS_USING_IMAGES_TO_ALIGN,
					Boolean.valueOf(true));
			exporter.setParameter(JRHtmlExporterParameter.IMAGES_URI,
					"/threadfix/jasper/images/");

			exporter.exportReport();

		} catch (JRException ex) {
			log.error("Encountered a Jasper exception, the report was probably not exported correctly.");
			ex.printStackTrace();
		}

		log.debug("Returning report.");
		
		try {
			if (inputStream != null)
				inputStream.close();
		} catch (IOException e) {
			log.warn("Failed to close an InputStream");
			e.printStackTrace();
		}
		
		return report;
	}

	public String getString(InputStream inputStream) {
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
		
		String line = null;
		StringBuffer buffer = new StringBuffer();
		try {
			while ((line = bufferedReader.readLine()) != null)
				buffer.append(line);
			
			bufferedReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return buffer.toString();
	}
	
	public InputStream getInputStream(String string) {
		if (string != null)
			return new ByteArrayInputStream(string.getBytes());
		else
			return null;
	}
	
	public List<ChannelType> getChannelTypesInUse(List<Integer> applicationIdList) {
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
	
	public InputStream addCorrectColumns(InputStream inputStream, List<Integer> applicationIdList) {
		log.debug("Adding the correct headers to the CWE Channel report Input Stream.");
		
		String string = getString(inputStream);
		
		List<ChannelType> channelTypeList = getChannelTypesInUse(applicationIdList);
		
		Integer base = 300, increment = 140, count = 0;
		
		for (ChannelType channelType : channelTypeList) {
			if (channelType == null || channelType.getId() == null)
				continue;
			String id = channelType.getId().toString();
			String location = String.valueOf(base + (count*increment));
			
			String sumLine = ", SUM(CASE WHEN scan.applicationChannel.channelType.id = " 
				+ id + " THEN 1 ELSE 0 END) as count_" + id + "\n";
			string = string.replaceFirst("FROM Finding", sumLine + "FROM Finding");
			
			String fieldTag = "<field name=\"count_" + id + "\" class=\"java.lang.Long\"/>\n";
			string = string.replaceFirst("<background>", fieldTag + "<background>");
			
			String textFieldTag = "\n<textField>\n"
				+ "<reportElement x=\"" + location + "\" y=\"0\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "\t<textElement verticalAlignment=\"Middle\"/>\n"
				+ "\t<textFieldExpression class=\"java.lang.Long\"><![CDATA[\\$F{count_"
				+ id
				+ "}]]></textFieldExpression>\n"
				+ "</textField>";
			string = string.replaceFirst("</band>	</detail", textFieldTag + "</band>	</detail");
			
			String headerText = "<staticText>\n"
				+ "<reportElement x=\"" + location + "\" y=\"22\" width=\"" + increment + "\" height=\"20\"/>\n"
				+ "<textElement verticalAlignment=\"Middle\"/>\n"
				+ "<text><![CDATA[" + channelType.getName() + "]]></text>\n"
				+ "</staticText>\n";
			string = string.replaceFirst("<line>", headerText + "<line>");
			
			count += 1;
		}
		
		return getInputStream(string);
	}
}
