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
package com.denimgroup.threadfix.service.channel;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
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

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.VulnerabilityMapLog;

/**
 * 
 * This class has a lot of methods that reduce code duplication and make writing
 * new importers much easier. The convenience methods are SAX-based.
 * To quickly write a new SAX importer, subclass DefaultHandler and pass a new instance
 * to parseSAXInput(). You can easily create Findings using constructFinding(). 
 * If you add your findings to the saxFindingList and the date inside the
 * date field from this class everything will parse correctly.
 * @author mcollins
 * 
 */
@Transactional(readOnly = true)
public abstract class AbstractChannelImporter implements ChannelImporter {

	// this.getClass() will turn into the individual importer name at runtime.
	protected final Log log = LogFactory.getLog(this.getClass());
	protected static final String FILE_CHECK_COMPLETED = "File check completed.";
	
	// These keys and the new constructFinding() method can be used to write new importers more quickly.
	protected static final String CHANNEL_VULN_KEY = "channelVulnerabilityCode";
	protected static final String PATH_KEY = "path";
	protected static final String PARAMETER_KEY = "parameter";
	protected static final String CHANNEL_SEVERITY_KEY = "channelSeverityCode";
	
	// A stream pointing to the scan's contents. Set with either setFile or
	// setFileName.
	protected InputStream inputStream;
	
	protected String testStatus;

	protected ChannelType channelType;
	protected ApplicationChannel applicationChannel;

	protected Map<String, ChannelSeverity> channelSeverityMap;
	protected Map<String, ChannelVulnerability> channelVulnerabilityMap;

	protected ChannelVulnerabilityDao channelVulnerabilityDao;
	protected ChannelSeverityDao channelSeverityDao;
	protected ChannelTypeDao channelTypeDao;
	protected GenericVulnerabilityDao genericVulnerabilityDao;
	protected VulnerabilityMapLogDao vulnerabilityMapLogDao;

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

	/**
	 * Sets the filename containing the scan results.
	 * 
	 * @param file
	 *            The file containing the scan results.
	 * @throws IOException
	 *             Thrown if the file cannot be accessed.
	 */
	@Override
	public void setFile(MultipartFile file) {
		try {
			this.inputFileName = file.getOriginalFilename();
			this.inputStream = file.getInputStream();
		} catch (IOException e) {
			e.printStackTrace();
		}
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
			e.printStackTrace();
		}
	}
	
	@Override
	public void setInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
	}

	@Override
	public void deleteScanFile() {
		try {
			inputStream.close();
			File file = new File(inputFileName);
			if (file.exists()) {
				if (!file.delete()) {
					log.warn("Scan file deletion failed, calling deleteOnExit()");
					file.deleteOnExit();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected void deleteZipFile() {
		if (zipFile != null)
			try {
				zipFile.close();
			} catch (IOException e) {
				log.warn("Closing zip file failed in deleteZipFile() in AbstractChannelImporter.", e);
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
		if (param == null)
			param = "";

		if (type == null)
			type = "";

		if (url == null)
			url = "";
		else if (url.indexOf('/') == 0)
			url = url.substring(1);

		String toHash = type.toLowerCase().trim() + url.toLowerCase().trim()
				+ param.toLowerCase().trim();
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(toHash.getBytes(), 0, toHash.length());
			return new BigInteger(1, messageDigest.digest()).toString(16);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * This method can be used to construct a finding out of the 
	 * important common information that findings have.
	 */
	
	protected Finding constructFinding(Map<String, String> findingMap) {
		if (findingMap == null || findingMap.size() == 0)
			return null;
		
		return constructFinding(findingMap.get(PATH_KEY), findingMap.get(PARAMETER_KEY), 
				findingMap.get(CHANNEL_VULN_KEY), findingMap.get(CHANNEL_SEVERITY_KEY));
	}
	
	/*
	 * This method can be used to construct a finding out of the 
	 * important common information that findings have.
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
				if (hosts != null)
					for (String host : hosts)
		    			if (url.startsWith(host)) {
		    				location.setHost(host);
			    			location.setPath("/" + url.substring(host.length()));
		    			}
	    		
	    		if (location.getPath() == null)
	    			location.setPath(url);
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

		if (sourceFileName.contains("\\"))
			sourceFileName = sourceFileName.replace("\\", "/");

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
			if (!sourceFileName.toLowerCase().contains(val))
				continue;

			String temp = getRegexResult(sourceFileName.toLowerCase(), "(/" + val + "/.+)");
			if (temp != null) {
				sourceFileName = temp;
				parsedFlag = true;
				break;
			}
		}

		for (String val : suffixVals) {
			if (!sourceFileName.contains(val))
				continue;

			String temp = getRegexResult(sourceFileName, "(.+\\." + val + ")");
			if (temp != null)
				return temp.toLowerCase();
		}

		if (parsedFlag) {
			return sourceFileName;
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
	protected void closeInputStream() {
		if (inputStream != null) {
			try {
				inputStream.close();
			} catch (IOException ex) {
				log.warn("Closing an input stream failed.");
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
			// CSVLogFile used to capture output for fortify csv and other
			// importers as necessary.
			// writeCSVLogFile(code, channelVulnerabilityMap.get(code),
			// channelVulnerabilityMap.get(code).getName());
			return channelVulnerabilityMap.get(code);
		} else {
			ChannelVulnerability vuln = channelVulnerabilityDao.retrieveByCode(channelType, code);
			if (vuln == null) {
				if (channelType != null)
					log.warn("A " + channelType.getName() + " channel vulnerability with code "
						+ code + " was requested but not found.");
				writeLogFile(code, "This channel vulnerability was not found");
				return null;
			} else {
				if (vuln.getGenericVulnerability() == null) {
					writeLogFile(vuln.getName(), "no generic vuln found");
				}
			}

			channelVulnerabilityMap.put(code, vuln);
			return vuln;
		}
	}


	/*
	 * This method writes to the vulnerabilityMapLog table in the database.
	 * Now it is used to record instances where channel vulnerabilities
	 * did not have the proper mapping in the database.
	 */
	@Transactional(readOnly = false)
	protected void writeLogFile(String channelVulnName, String comment) {
		if (channelVulnName == null || channelType == null)
			return;

		if (vulnerabilityMapLogDao == null
				|| vulnerabilityMapLogDao.retrieveByChannelVulnNameAndChannelType(channelVulnName,
						channelType) != null)
			return;
			
		VulnerabilityMapLog mapLog = new VulnerabilityMapLog();
		mapLog.setChannelType(channelType);
		mapLog.setComment(comment);
		mapLog.setResolved(false);
		mapLog.setChannelVulnName(channelVulnName);
		vulnerabilityMapLogDao.saveOrUpdate(mapLog);
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
			e.printStackTrace();
		}

		if (date != null) {
			log.debug("Successfully parsed date: " + date.toString() + ".");
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
				log.warn("There was a failure trying to read a file from a zip.");
				e.printStackTrace();
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
			
		try {
			if (diskZipFile.exists()) {
				log.info("The file was on disk, wrapping it in a ZipFile and returning.");
				return new ZipFile(diskZipFile);
			}

			FileOutputStream out = new FileOutputStream(diskZipFile);
			byte buf[] = new byte[1024];
			int len = 0;

			while ((len = inputStream.read(buf)) > 0)
				out.write(buf, 0, len);
			
			out.close();
			ZipFile zipFile = new ZipFile(diskZipFile);
			
			log.debug("Saved zip file to disk. Returning zip file.");
			
			return zipFile;
		} catch (ZipException e) {
			log.warn("There was a ZipException while trying to save and open the file - probably not in a zip format.");
		} catch (IOException e) {
			log.warn("There was an IOException error in the unpackZipStream method: " + e + ".");
		}
		
		return null;
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
		
		if (saxFindingList == null)
			saxFindingList = new ArrayList<Finding>();
				
		readSAXInput(handler, "Done Parsing.");
		
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
	protected String testSAXInput(DefaultHandler handler) {
		log.debug("Starting SAX Test.");
		
		if (inputStream == null) {
			log.warn(NULL_INPUT_ERROR);
			return NULL_INPUT_ERROR;
		}
		
		if (doSAXExceptionCheck && isBadXml(inputStream)) {
			log.warn("Bad XML format - ensure correct, uniform encoding.");
			return BADLY_FORMED_XML;
		}
		
		readSAXInput(handler, FILE_CHECK_COMPLETED);

		if (inputFileName != null) 
			deleteScanFile();
		
		log.info(testStatus);
		return testStatus;
	}

	// This method checks through the XML with a blank parser to determine
	// whether SAX parsing will fail due to an exception.
	protected boolean isBadXml(InputStream inputStream) {
		try {
			readSAXInput(new DefaultHandler());
		} catch (SAXException e) {
			return true;
		} catch (IOException e) {
			return true;
		}

		return false;
	}
	
	// This method with one argument sets up the SAXParser and inputStream correctly
	// and executes the parsing. With two it adds a completion code and exception handling.
	protected void readSAXInput(DefaultHandler handler, String completionCode) {
		try {
			readSAXInput(handler);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			if (!e.getMessage().equals(completionCode))
				e.printStackTrace();
		}
	}
	
	protected void readSAXInput(DefaultHandler handler) throws SAXException, IOException {
		XMLReader xmlReader = XMLReaderFactory.createXMLReader();
		xmlReader.setContentHandler(handler);
		xmlReader.setErrorHandler(handler);
		
		byte [] byteArray = IOUtils.toByteArray(inputStream);
		
		// Wrapping the inputStream in a BufferedInputStream allows us to mark and reset it
		inputStream = new BufferedInputStream(new ByteArrayInputStream(byteArray));
		
		// UTF-8 contains 3 characters at the start of a file, which is a problem.
		// The SAX parser sees them as characters in the prolog and throws an exception.
		// This code removes them if they are present.
		inputStream.mark(4);
		
		if (inputStream.read() == 239) {
			inputStream.read(); inputStream.read();
		} else
			inputStream.reset();
		
		Reader fileReader = new InputStreamReader(inputStream,"UTF-8");
		InputSource source = new InputSource(fileReader);
		source.setEncoding("UTF-8");
		xmlReader.parse(source);
		closeInputStream();
		inputStream = new ByteArrayInputStream(byteArray);
	}
	
	protected String checkTestDate() {
		if (applicationChannel == null || testDate == null)
			return OTHER_ERROR;
		
		List<Scan> scanList = applicationChannel.getScanList();
		
		for (Scan scan : scanList) {
			if (scan != null && scan.getImportTime() != null) {
				int result = scan.getImportTime().compareTo(testDate);
				if (result == 0)
					return DUPLICATE_ERROR;
				else if (result > 0)
					return OLD_SCAN_ERROR;
			}
		}
		
		return SUCCESSFUL_SCAN;
	}
	
	/**
	 * Parses the text from the SAX DefaultHandler getCharacters() method into a String.
	 * 
	 * @param ch
	 * @param start
	 * @param length
	 * @return
	 */
	protected String getText(char ch[], int start, int length) {
		char [] mychars = new char[length];
		
		System.arraycopy(ch, start, mychars, 0, length);

		return new String(mychars);
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
