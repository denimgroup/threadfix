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
package com.denimgroup.threadfix.service.channel;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import org.apache.commons.lang.StringEscapeUtils;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanUtils;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * This class has a lot of methods that reduce code duplication and make writing
 * new importers much easier. The convenience methods are SAX-based.
 * To quickly write a new SAX importer, subclass DefaultHandler and pass a new instance
 * to parseSAXInput(). You can easily create Findings using constructFinding(). 
 * If you add your findings to the saxFindingList and the date inside the
 * date field from this class everything will parse correctly.
 * 
 * <br><br>
 * 
 * Note that RemoteProviders also implement this class.
 * 
 * @author mcollins
 * 
 */
@Transactional(readOnly = true)
public abstract class AbstractChannelImporter implements ChannelImporter {

	// this.getClass() will turn into the individual importer name at runtime.
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
	protected static final String FILE_CHECK_COMPLETED = "File check completed.";
	
	protected enum FindingKey {
		VULN_CODE, PATH, PARAMETER, SEVERITY_CODE, NATIVE_ID
	}
	
	// A stream pointing to the scan's contents. Set with either setFile or
	// setFileName.
	protected InputStream inputStream;
	
	protected ScanImportStatus testStatus;

	protected ChannelType channelType;
	protected ApplicationChannel applicationChannel;

	protected Map<String, ChannelSeverity> channelSeverityMap;
	protected Map<String, ChannelVulnerability> channelVulnerabilityMap;

	protected ChannelVulnerabilityDao channelVulnerabilityDao;
	protected ChannelSeverityDao channelSeverityDao;
	protected ChannelTypeDao channelTypeDao;
	protected GenericVulnerabilityDao genericVulnerabilityDao;

	protected String inputFileName;
	
	protected ZipFile zipFile;
	protected File diskZipFile;
	
	protected List<String> hosts;
	protected List<Finding> saxFindingList;
	
	protected Calendar date = null;
	protected Calendar testDate = null;
	
	protected boolean doSAXExceptionCheck = true;
	
	@Override
	public void setChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}
	
	@Override
	public Calendar getTestDate() {
		return testDate;
	}

	/**
	 * Sets the filename containing the scan results.
	 * 
	 * @param fileName
	 *            The file containing the scan results.
	 */
	@Override
	public void setFileName(String fileName) {
		try {
			this.inputStream = new FileInputStream(fileName);
			this.inputFileName = new File(fileName).getAbsolutePath();
		} catch (FileNotFoundException e) {
			log.warn("It appears that the scan file did not save correctly and is therefore not available to the scan file parser",e);
		}
	}
	
	@Override
	public void setInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
	}

	@Override
	public void deleteScanFile() {
		
		closeInputStream(inputStream);
		
		File file = new File(inputFileName);
		if (file.exists()) {
			if (!file.delete()) {
				log.warn("Scan file deletion failed, calling deleteOnExit()");
				file.deleteOnExit();
			}
		}
	}

	protected void deleteZipFile() {
		if (zipFile != null) {
			try {
				zipFile.close();
			} catch (IOException e) {
				log.warn("Closing zip file failed in deleteZipFile() in AbstractChannelImporter.", e);
			}
		}
		
		if (diskZipFile != null && !diskZipFile.delete()) {
			log.warn("Zip file deletion failed, calling deleteOnExit()");
			diskZipFile.deleteOnExit();
		}
	}

	/**
	 * @param channelTypeCode
	 */
	protected void setChannelType(String channelTypeCode) {
		channelType = channelTypeDao.retrieveByName(channelTypeCode);
	}

	/**
	 * 
	 */
	protected void initializeMaps() {
		channelSeverityMap = new HashMap<String, ChannelSeverity>();
		channelVulnerabilityMap = new HashMap<String, ChannelVulnerability>();
	}

	/**
	 * Hashes whatever three strings are given to it.
	 * 
	 * @param type
	 *            The generic, CWE type of vulnerability.
	 * @param url
	 *            The URL location of the vulnerability.
	 * @param param
	 *            The vulnerable parameter (optional)
	 * @throws NoSuchAlgorithmException
	 *             Thrown if the MD5 algorithm cannot be found.
	 * @return The three strings concatenated, downcased, trimmed, and hashed.
	 */
	protected String hashFindingInfo(String type, String url, String param) {
		StringBuffer toHash = new StringBuffer();
		
		if (type != null) {
			toHash = toHash.append(type.toLowerCase().trim());
		}
		
		if (url != null) {
			if (url.indexOf('/') == 0 || url.indexOf('\\') == 0) {
				toHash = toHash.append(url.substring(1).toLowerCase().trim());
			} else {
				toHash = toHash.append(url.toLowerCase().trim());
			}
		}
		
		if (param != null) {
			toHash = toHash.append(param.toLowerCase().trim());
		}

		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(toHash.toString().getBytes(), 0, toHash.length());
			return new BigInteger(1, messageDigest.digest()).toString(16);
		} catch (NoSuchAlgorithmException e) {
			log.error("Can't find MD5 hash function to hash finding info", e);
			return null;
		}
	}
	
	/*
	 * This method can be used to construct a finding out of the 
	 * important common information that findings have.
	 */
	
	protected Finding constructFinding(Map<FindingKey, String> findingMap) {
		if (findingMap == null || findingMap.size() == 0)
			return null;
		
		return constructFinding(findingMap.get(FindingKey.PATH), 
				findingMap.get(FindingKey.PARAMETER), 
				findingMap.get(FindingKey.VULN_CODE), 
				findingMap.get(FindingKey.SEVERITY_CODE)); 
	}
	
	/**
	 *
	 * This method can be used to construct a finding out of the 
	 * important common information that findings have.
	 * @param url
	 * @param parameter
	 * @param channelVulnerabilityCode
	 * @param channelSeverityCode
	 * @return
	 */
	protected Finding constructFinding(String url, String parameter, 
    		String channelVulnerabilityCode, String channelSeverityCode) {
    	if (channelVulnerabilityCode == null || channelVulnerabilityCode.isEmpty())
    		return null;
    	
    	Finding finding = new Finding();
		SurfaceLocation location = new SurfaceLocation();
		
		if (url != null && !url.isEmpty())
			try {
				location.setUrl(new URL(url));
			} catch (MalformedURLException e) {
				if (hosts != null) {
					for (String host : hosts) {
		    			if (url.startsWith(host)) {
		    				location.setHost(host);
			    			location.setPath("/" + url.substring(host.length()));
		    			}
					}
				}
	    		
	    		if (location.getPath() == null) {
	    			location.setPath(url);
	    		}
			}
		
		if (parameter != null && !parameter.isEmpty())
			location.setParameter(parameter);
		
		// We need to ensure that validation succeeds and that none of the Strings are too long.
		if (location.getHost() != null && location.getHost().length() > SurfaceLocation.HOST_LENGTH)
			location.setHost(location.getHost().substring(0, SurfaceLocation.HOST_LENGTH - 1));
		if (location.getParameter() != null && location.getParameter().length() > SurfaceLocation.PARAMETER_LENGTH)
			location.setParameter(location.getParameter().substring(0, SurfaceLocation.PARAMETER_LENGTH - 1));
		if (location.getPath() != null && location.getPath().length() > SurfaceLocation.PATH_LENGTH)
			location.setPath(location.getPath().substring(0, SurfaceLocation.PATH_LENGTH - 1));
		if (location.getQuery() != null && location.getQuery().length() > SurfaceLocation.QUERY_LENGTH)
			location.setQuery(location.getQuery().substring(0, SurfaceLocation.QUERY_LENGTH - 1));
		
		finding.setSurfaceLocation(location);
		
		ChannelVulnerability channelVulnerability = null;
		if (channelVulnerabilityCode != null)
			channelVulnerability = getChannelVulnerability(channelVulnerabilityCode);
		finding.setChannelVulnerability(channelVulnerability);
		
		ChannelSeverity channelSeverity = null;
		if (channelSeverityCode != null)
			channelSeverity = getChannelSeverity(channelSeverityCode);
		finding.setChannelSeverity(channelSeverity);
			    		
		return finding;
    }

	/**
	 * Attempts to guess the URL given a file name. TODO Make this method better
	 * 
	 * @param sourceFileName
	 *            The file name.
	 * @return the URL
	 */
	protected String convertSourceFileNameToUrl(String sourceFileName, String applicationRoot) {
		if (sourceFileName == null)
			return null;
		
		String editedSourceFileName = sourceFileName;

		if (editedSourceFileName.contains("\\"))
			editedSourceFileName = editedSourceFileName.replace("\\", "/");

		boolean parsedFlag = false;

		// TODO - Make a better, more generic way of identifying web root
		// directory names
		// maybe ask the user for the application root / use it as the
		// application url
		String[] prefixVals = { "wwwroot", "web", "cgi-bin", "cgi", ""};
		if(applicationRoot != null && !applicationRoot.trim().equals("")){
			prefixVals[4] = applicationRoot.toLowerCase();
		}
		String[] suffixVals = { "aspx", "asp", "jsp", "php", "html", "htm", "java", "cs", "config",
				"js", "cgi", "ascx" };

		for (String val : prefixVals) {
			if (!editedSourceFileName.toLowerCase().contains(val))
				continue;

			String temp = getRegexResult(editedSourceFileName.toLowerCase(), "(/" + val + "/.+)");
			if (temp != null) {
				editedSourceFileName = temp;
				parsedFlag = true;
				break;
			}
		}

		for (String val : suffixVals) {
			if (!editedSourceFileName.contains(val))
				continue;

			String temp = getRegexResult(editedSourceFileName, "(.+\\." + val + ")");
			if (temp != null)
				return temp.toLowerCase();
		}

		if (parsedFlag) {
			return editedSourceFileName;
		} else {
			return null;
		}
	}

	/**
	 * Utility to prevent declaring a bunch of Matchers and Patterns.
	 * 
	 * @param targetString
	 * @param regex
	 * @return result of applying Regex
	 */
	protected String getRegexResult(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty()) {
			log.warn("getRegexResult got null or empty input.");
			return null;
		}

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
	}

	/**
	 * @param stream
	 */
	protected void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				log.warn("Closing an input stream failed.", ex);
			}
		}
	}

	/**
	 * If the channelType is set and the severity code is in the DB this method
	 * will pull it up.
	 * 
	 * @param code
	 * @return the correct severity from the DB.
	 */
	protected ChannelSeverity getChannelSeverity(String code) {
		if (channelType == null || code == null || channelSeverityDao == null)
			return null;

		if (channelSeverityMap == null)
			initializeMaps();

		ChannelSeverity severity = channelSeverityMap.get(code);
		if (severity == null) {
			severity = channelSeverityDao.retrieveByCode(channelType, code);
			if (severity != null) {
				channelSeverityMap.put(code, severity);
			}
		}

		return severity;
	}

	/**
	 * If the channelType is set and the vulnerability code is in the DB this
	 * method will pull it up.
	 * 
	 * @param code
	 * @return vulnerability from the DB
	 */

	protected ChannelVulnerability getChannelVulnerability(String code) {
		if (channelType == null || code == null || channelVulnerabilityDao == null)
			return null;
		
		if (channelVulnerabilityMap == null)
			initializeMaps();

		if (channelVulnerabilityMap == null)
			return null;

		if (channelVulnerabilityMap.containsKey(code)) {
			return channelVulnerabilityMap.get(code);
		} else {
			ChannelVulnerability vuln = channelVulnerabilityDao.retrieveByCode(channelType, code);
			if (vuln == null) {
				if (channelType != null)
					log.warn("A " + channelType.getName() + " channel vulnerability with code "
						+ StringEscapeUtils.escapeHtml(code) + " was requested but not found.");
				return null;
			} else {
				if (channelVulnerabilityDao.hasMappings(vuln.getId())) {
					log.info("The " + channelType.getName() + " channel vulnerability with code "
						+ StringEscapeUtils.escapeHtml(code) + " has no generic mapping.");
				}
			}

			channelVulnerabilityMap.put(code, vuln);
			return vuln;
		}
	}

	// return the parsed date object, or the null if parsing fails.
	protected Calendar getCalendarFromString(String formatString, String dateString) {
		if (formatString == null || formatString.trim().equals("") ||
				dateString == null || dateString.trim().equals("") )
			return null;

		Date date = null;
		try {
			date = new SimpleDateFormat(formatString, Locale.US).parse(dateString);
		} catch (ParseException e) {
			log.warn("Parsing of date from '" + dateString + "' failed.", e);
		}

		if (date != null) {
			log.debug("Successfully parsed date: " + date + ".");
			Calendar scanTime = new GregorianCalendar();
			scanTime.setTime(date);
			return scanTime;
		}
		
		log.warn("There was an error parsing the date, check the format and regex.");
		return null;
	}
	
	/*
	 * These methods help you deal with zip files. unpackZipStream() parses your inputStream
	 * and stores it in zipFile, and then you can access file from it with the correct path 
	 * using this method.
	 */
	protected InputStream getFileFromZip(String fileName) {
		if (zipFile == null || fileName == null || fileName.trim().equals(""))
			return null;
		
		InputStream inputStream = null;

		ZipEntry auditFile = zipFile.getEntry(fileName);
		if (auditFile != null) {
			try {
				inputStream = zipFile.getInputStream(auditFile);
			} catch (IOException e) {
				log.warn("There was a failure trying to read a file from a zip.", e);
			}
		}

		return inputStream;
	}
	
	protected ZipFile unpackZipStream() {
		if (this.inputStream == null)
			return null;

		log.debug("Attempting to unpack the zip stream.");
	
		diskZipFile = new File("temp-zip-file");

		if (diskZipFile == null) {
			log.warn("The attempt to unpack the zip stream returned null.");
			return null;
		}
		
		ZipFile zipFile = null;
		FileOutputStream out = null;
		try {

			out = new FileOutputStream(diskZipFile);
			byte buf[] = new byte[1024];
			int len = 0;

			while ((len = inputStream.read(buf)) > 0)
				out.write(buf, 0, len);
			
			zipFile = new ZipFile(diskZipFile);
			
			log.debug("Saved zip file to disk. Returning zip file.");
		} catch (ZipException e) {
			log.warn("There was a ZipException while trying to save and open the file - probably not in a zip format.", e);
		} catch (IOException e) {
			log.warn("There was an IOException error in the unpackZipStream method: " + e + ".");
		} finally {
			closeInputStream(inputStream);
			if (out != null) {
				try {
					out.close();
				} catch (IOException ex) {
					log.warn("Closing an input stream failed.", ex);
				}
			}
		}
		
		return zipFile;
	}
	
	/**
	 * Hash the vulnerability name and the path and the parameter strings into a native ID.
	 * 
	 * @param finding
	 * @return
	 */
	protected String getNativeId(Finding finding) {
		if (finding == null || finding.getSurfaceLocation() == null)
			return null;

		String vulnName = null;
		if (finding.getChannelVulnerability() != null)
			vulnName = finding.getChannelVulnerability().getName();

		String nativeId = hashFindingInfo(vulnName, finding.getSurfaceLocation().getPath(), finding
				.getSurfaceLocation().getParameter());
		
		return nativeId;
	}
	
	/**
	 * This method wraps a lot of functionality that was previously seen in multiple importers
	 * into one method to reduce duplication. It sets up the relationship between the subclassed
	 * handler and the main importer, cleans and wraps the file in an InputSource, and parses it.
	 * It relies on the fact that there is a common instance variable named saxFindingList that 
	 * the handlers are putting their Findings in, and the variable date that the parsers are putting
	 * the date in.
	 * @param handler
	 * @return
	 */
	protected Scan parseSAXInput(DefaultHandler handler) {
		log.debug("Starting SAX Parsing.");
		
		if (inputStream == null)
			return null;
		
		saxFindingList = new ArrayList<Finding>();
				
		ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);
		
		Scan scan = new Scan();
		scan.setFindings(saxFindingList);
		scan.setApplicationChannel(applicationChannel);
		
		if ((date != null) && (date.getTime() != null)) {
			log.debug("SAX Parser found the scan date: " + date.getTime().toString());
			scan.setImportTime(date);
		} else {
			log.warn("SAX Parser did not find the date.");
		}

		if (scan.getFindings() != null && scan.getFindings().size() != 0)
			log.debug("SAX Parsing successfully parsed " + scan.getFindings().size() +" Findings.");
		else
			log.warn("SAX Parsing did not find any Findings.");
		
		if (inputFileName != null) 
			deleteScanFile();
				
		return scan;
	}
	
	/**
	 * This method wraps a lot of functionality that was previously seen in multiple importers
	 * into one method to reduce duplication. It sets up the relationship between the subclassed
	 * handler and the main importer, cleans and wraps the file in an InputSource, and parses it.
	 * It relies on the fact that there is a common instance variable named saxFindingList that 
	 * the handlers are putting their Findings in, and the variable date that the parsers are putting
	 * the date in.
	 * @param handler
	 * @return
	 */
	protected ScanCheckResultBean testSAXInput(DefaultHandler handler) {
		log.debug("Starting SAX Test.");
		
		if (inputStream == null) {
			log.warn(ScanImportStatus.NULL_INPUT_ERROR.toString());
			return new ScanCheckResultBean(ScanImportStatus.NULL_INPUT_ERROR);
		}
		
		if (doSAXExceptionCheck) {
			if (ScanUtils.isBadXml(inputStream)) {
				log.warn("Bad XML format - ensure correct, uniform encoding.");
				return new ScanCheckResultBean(ScanImportStatus.BADLY_FORMED_XML);
			}
			closeInputStream(inputStream);
			try {
				inputStream = new FileInputStream(inputFileName);
			} catch (FileNotFoundException e) {
				log.error("Cannot find file '" + inputFileName + "'.", e);
			}
		}
		
		ScanUtils.readSAXInput(handler, FILE_CHECK_COMPLETED, inputStream);
		closeInputStream(inputStream);
		
		log.info("Scan status: " + testStatus);
		return new ScanCheckResultBean(testStatus, testDate);
	}

	/**
	 * This method requires that the AbstractChannelImporter fields
	 * applicationChannel and testDate have valid values.
	 * 
	 * It returns either a duplicate, old scan, or unidentified error,
	 * or a success code.
	 * @return
	 */
	protected ScanImportStatus checkTestDate() {
		if (applicationChannel == null || testDate == null)
			return ScanImportStatus.OTHER_ERROR;
		
		List<Scan> scanList = applicationChannel.getScanList();
		
		if (scanList != null) {
			for (Scan scan : scanList) {
				if (scan != null && scan.getImportTime() != null) {
					int result = scan.getImportTime().compareTo(testDate);
					if (result == 0)
						return ScanImportStatus.DUPLICATE_ERROR;
					else if (result > 0)
						return ScanImportStatus.OLD_SCAN_ERROR;
				}
			}
		}
		
		return ScanImportStatus.SUCCESSFUL_SCAN;
	}

	/**
	 * 
	 * HTTP traffic all follows a pattern, so if you can see an HTTP response then you 
	 * can parse out the date the request was made. This method does that.
	 * @param httpTrafficString
	 * @return
	 */
	protected Calendar attemptToParseDateFromHTTPResponse(String httpTrafficString) {
		if (httpTrafficString == null)
			return null;
		
		String dateString = getRegexResult(httpTrafficString, "Date: ([^\n]+)");
		
		if (dateString != null && !dateString.isEmpty())
			return getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss zzz", dateString);
		else
			return null;
	}
}
