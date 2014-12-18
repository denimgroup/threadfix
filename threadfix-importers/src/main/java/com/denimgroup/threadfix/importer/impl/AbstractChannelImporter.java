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
package com.denimgroup.threadfix.importer.impl;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.exception.ScanFileUnavailableException;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 *
 * WARNING: Do not reference this class outside of this plugin. It is subject to change
 * without notice.
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
public abstract class AbstractChannelImporter extends SpringBeanAutowiringSupport implements ChannelImporter {

    // this.getClass() will turn into the individual importer name at runtime.
    protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
    protected static final String FILE_CHECK_COMPLETED = "File check completed.";

    protected enum FindingKey {
        VULN_CODE, PATH, PARAMETER, SEVERITY_CODE, NATIVE_ID, CVE, CWE, VALUE, REQUEST, RESPONSE, DETAIL,
        RECOMMENDATION, RAWFINDING, URL_REFERENCE
    }

    // A stream pointing to the scan's contents. Set with either setFile or
    // setFileName.
    protected InputStream inputStream;

    protected ScanImportStatus testStatus;

    protected ChannelType channelType;
    protected ApplicationChannel applicationChannel;

    protected Map<String, ChannelSeverity> channelSeverityMap;
    protected Map<String, ChannelVulnerability> channelVulnerabilityMap;

    public boolean shouldDeleteAfterParsing = true;

    @Autowired
    protected ChannelVulnerabilityDao channelVulnerabilityDao;
    @Autowired
    protected ChannelSeverityDao channelSeverityDao;
    @Autowired
    protected ChannelTypeDao channelTypeDao;
    @Autowired
    protected GenericVulnerabilityDao genericVulnerabilityDao;

    protected String channelTypeCode;

    public AbstractChannelImporter(@Nonnull ScannerType channelTypeName) {
        this.channelTypeCode = channelTypeName.getDbName();
    }

    public AbstractChannelImporter(@Nonnull String channelTypeName) {
        this.channelTypeCode = channelTypeName;
    }

    protected ChannelType getChannelType() {
        if (channelType == null) {
            if (channelTypeDao == null) {
                throw new IllegalStateException("Spring is incorrectly configured, and scans cannot continue.");
            }

            channelType = channelTypeDao.retrieveByName(channelTypeCode);

            if (channelType == null) {
                throw new IllegalStateException("The database is not set up correctly: there was no entry for " +
                        channelTypeCode);
            }
        }
        return channelType;
    }

    @Nullable
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
            log.warn("It appears that the scan file did not save correctly and is " +
                    "therefore not available to the scan file parser", e);
        }
    }

    @Override
    public void setInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public void deleteScanFile() {

        closeInputStream(inputStream);

        if (shouldDeleteAfterParsing && inputFileName != null) {
            File file = new File(inputFileName);
            if (file.exists()) {
                if (!file.delete()) {
                    log.warn("Scan file deletion failed, calling deleteOnExit()");
                    file.deleteOnExit();
                }
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
     *
     */
    protected void initializeMaps() {
        channelSeverityMap = new HashMap<>();
        channelVulnerabilityMap = new HashMap<>();
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
     * @return The three strings concatenated, downcased, trimmed, and hashed.
     */
    @Nonnull
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
            log.debug("REMOVEME: To be hashed (not including quotes):'" + toHash+"'");
            String hash = new BigInteger(1, messageDigest.digest()).toString(16);
            log.debug("Hash: " + hash);
            return hash;
        } catch (NoSuchAlgorithmException e) {
            log.error("Can't find MD5 hash function to hash finding info", e);
            throw new IllegalStateException("MD5 library couldn't be loaded.");
        }
    }

    /**
     *
     * This method can be used to construct a finding out of the
     * important common information that findings have.
     */
    @Nullable
    protected Finding constructFinding(String url, String parameter,
                                       String channelVulnerabilityCode, String channelSeverityCode) {
        Map<FindingKey, String> findingMap = new HashMap<>();
        findingMap.put(FindingKey.PATH, url);
        findingMap.put(FindingKey.PARAMETER, parameter);
        findingMap.put(FindingKey.VULN_CODE, channelVulnerabilityCode);
        findingMap.put(FindingKey.SEVERITY_CODE, channelSeverityCode);
        return constructFinding(findingMap);
    }

    /**
     *
     * This method can be used to construct a finding out of the
     * important common information that findings have.
     */
    @Nullable
    protected Finding constructFinding(String url, String parameter,
                                       String channelVulnerabilityCode, String channelSeverityCode, String cweCode) {
        Map<FindingKey, String> findingMap = new HashMap<>();
        findingMap.put(FindingKey.PATH, url);
        findingMap.put(FindingKey.PARAMETER, parameter);
        findingMap.put(FindingKey.VULN_CODE, channelVulnerabilityCode);
        findingMap.put(FindingKey.SEVERITY_CODE, channelSeverityCode);
        findingMap.put(FindingKey.CWE, cweCode);
        return constructFinding(findingMap);
    }

    /*
     * This method can be used to construct a finding out of the
     * important common information that findings have.
     */
    @Nullable
    protected Finding constructFinding(Map<FindingKey, String> findingMap) {

        if (findingMap == null || findingMap.size() == 0) {
            return null;
        }

        String url = findingMap.get(FindingKey.PATH);
        String parameter = findingMap.get(FindingKey.PARAMETER);
        String channelVulnerabilityCode = findingMap.get(FindingKey.VULN_CODE);
        String channelSeverityCode = findingMap.get(FindingKey.SEVERITY_CODE);
        String cweCode = findingMap.get(FindingKey.CWE);

        if (channelVulnerabilityCode == null || channelVulnerabilityCode.isEmpty()) {
            return null;
        }

        Finding finding = new Finding();
        SurfaceLocation location = new SurfaceLocation();

        // unify URLs
        Map<String,String> patterns = new HashMap<String,String>();
        patterns.put(";jsessionid=.*",";jsessionid=[removed]");
        patterns.put("/_ns:.*?/","/_ns:[removed]/");
        patterns.put("=[^/]*","=[removed]");

        for ( String match : patterns.keySet()){
            if (url != null && url.matches(".*" + match + ".*")){
                url = url.replaceAll(match, patterns.get(match));
            }
        }

        if (url != null && !url.isEmpty()) {
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
        }

        if (parameter != null && !parameter.isEmpty()) {
            location.setParameter(parameter);
        }

        // We need to ensure that validation succeeds and that none of the Strings are too long.
        if (location.getHost() != null && location.getHost().length() > SurfaceLocation.HOST_LENGTH) {
            location.setHost(location.getHost().substring(0, SurfaceLocation.HOST_LENGTH - 1));
        }
        if (location.getParameter() != null && location.getParameter().length() > SurfaceLocation.PARAMETER_LENGTH) {
            location.setParameter(location.getParameter().substring(0, SurfaceLocation.PARAMETER_LENGTH - 1));
        }
        if (location.getPath() != null && location.getPath().length() > SurfaceLocation.PATH_LENGTH) {
            location.setPath(location.getPath().substring(0, SurfaceLocation.PATH_LENGTH - 1));
        }
        if (location.getQuery() != null && location.getQuery().length() > SurfaceLocation.QUERY_LENGTH) {
            location.setQuery(location.getQuery().substring(0, SurfaceLocation.QUERY_LENGTH - 1));
        }

        finding.setSurfaceLocation(location);

        addFindingDetail(finding, findingMap);

        ChannelVulnerability channelVulnerability = getChannelVulnerability(channelVulnerabilityCode);

        if (channelVulnerability == null) {
            channelVulnerability = new ChannelVulnerability();
            channelVulnerability.setChannelType(getChannelType());
            channelVulnerability.setCode(channelVulnerabilityCode);
            channelVulnerability.setName(channelVulnerabilityCode);
            channelVulnerability.setFindings(Arrays.asList(finding));
        }

        // Create new Vulnerability Map
        if ((channelVulnerability.getVulnerabilityMaps() == null || channelVulnerability.getVulnerabilityMaps().size() == 0)
                && cweCode != null && !cweCode.isEmpty()) {
            GenericVulnerability genericVuln = genericVulnerabilityDao.retrieveByDisplayId(Integer.valueOf(cweCode));
            if (genericVuln != null) {
                // Create new Vulnerability Map and hook to Channel Vulnerability
                VulnerabilityMap vulnMap = new VulnerabilityMap();
                vulnMap.setChannelVulnerability(channelVulnerability);
                vulnMap.setGenericVulnerability(genericVuln);
                vulnMap.setMappable(true);
                channelVulnerability.setVulnerabilityMaps(Arrays.asList(vulnMap));
            }
        }

        channelVulnerabilityDao.saveOrUpdate(channelVulnerability);
        finding.setChannelVulnerability(channelVulnerability);

        ChannelSeverity channelSeverity = null;
        if (channelSeverityCode != null) {
            channelSeverity = getChannelSeverity(channelSeverityCode);
        }
        finding.setChannelSeverity(channelSeverity);

        return finding;
    }

    protected void addFindingDetail(Finding finding, Map<FindingKey, String> findingMap) {
        String parameterValue = findingMap.get(FindingKey.VALUE);
        String request = findingMap.get(FindingKey.REQUEST);
        String response = findingMap.get(FindingKey.RESPONSE);
        String detail = findingMap.get(FindingKey.DETAIL);
        String recommendation = findingMap.get(FindingKey.RECOMMENDATION);
        String rawFinding = findingMap.get(FindingKey.RAWFINDING);
        String urlReference = findingMap.get(FindingKey.URL_REFERENCE);

        if (parameterValue != null && parameterValue.length() > Finding.ATTACK_STRING_LENGTH)
            parameterValue = parameterValue.substring(0,Finding.ATTACK_STRING_LENGTH-20) + "\n\n[truncated]\n";
        finding.setAttackString(parameterValue);

        if (request != null && request.length() > Finding.ATTACK_REQUEST_LENGTH)
            request = request.substring(0,Finding.ATTACK_REQUEST_LENGTH-20) + "\n\n[truncated]\n";
        finding.setAttackRequest(request);

        if (response != null && response.length() > Finding.ATTACK_RESPONSE_LENGTH)
            response = response.substring(0,Finding.ATTACK_RESPONSE_LENGTH-20) + "\n\n[truncated]\n";
        finding.setAttackResponse(response);

        if (detail != null && detail.length() > Finding.SCANNER_DETAIL_LENGTH)
            detail = detail.substring(0,Finding.SCANNER_DETAIL_LENGTH-20) + "\n\n[truncated]\n";
        finding.setScannerDetail(detail);

        if (recommendation != null && recommendation.length() > Finding.SCANNER_RECOMMENDATION_LENGTH)
            recommendation = recommendation.substring(0,Finding.SCANNER_RECOMMENDATION_LENGTH-20) + "\n\n[truncated]\n";
        finding.setScannerRecommendation(recommendation);

        if (rawFinding != null && rawFinding.length() > Finding.RAW_FINDING_LENGTH)
            rawFinding = rawFinding.substring(0,Finding.RAW_FINDING_LENGTH-20) + "\n\n[truncated]\n";
        finding.setRawFinding(rawFinding);

        if (urlReference != null && urlReference.length() > Finding.URL_REFERENCE_LENGTH)
            urlReference = urlReference.substring(0,Finding.URL_REFERENCE_LENGTH-20) + "\n\n[truncated]\n";
        finding.setUrlReference(urlReference);
    }

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
     * @return the correct severity from the DB.
     */
    protected ChannelSeverity getChannelSeverity(String code) {
        if (getChannelType() == null || code == null || channelSeverityDao == null) {
            return null;
        }

        if (channelSeverityMap == null) {
            initializeMaps();
        }

        ChannelSeverity severity = channelSeverityMap.get(code);
        if (severity == null) {
            severity = channelSeverityDao.retrieveByCode(getChannelType(), code);
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
     * @param code channel vulnerability's code
     * @return vulnerability from the DB
     */
    protected ChannelVulnerability getChannelVulnerability(String code) {
        assert channelVulnerabilityDao != null;

        if (getChannelType() == null || code == null) {
            return null;
        }

        if (channelVulnerabilityMap == null) {
            initializeMaps();
            assert channelVulnerabilityMap != null;
        }

        if (channelVulnerabilityMap.containsKey(code)) {
            return channelVulnerabilityMap.get(code);
        } else {
            ChannelVulnerability vuln = channelVulnerabilityDao.retrieveByCode(getChannelType(), code);
            if (vuln == null) {
                if (getChannelType() != null) {
                    log.info("A " + getChannelType().getName() + " channel vulnerability with code "
                            + StringEscapeUtils.escapeHtml4(code) + " was requested but not found. " +
                            "Creating new ChannelVulnerability.");
                }
                vuln = createNewChannelVulnerability(getChannelType(), code);
            } else {
                if (channelVulnerabilityDao.hasMappings(vuln.getId())) {
                    log.info("The " + getChannelType().getName() + " channel vulnerability with code "
                            + StringEscapeUtils.escapeHtml4(code) + " has no generic mapping.");
                }
            }

            channelVulnerabilityMap.put(code, vuln);
            return vuln;
        }
    }

    // Create and save a new mapping
    // TODO Actually parse the name out too
    private ChannelVulnerability createNewChannelVulnerability(ChannelType channelType, String code) {
        ChannelVulnerability newChannelVulnerability = new ChannelVulnerability();
        newChannelVulnerability.setChannelType(channelType);
        newChannelVulnerability.setCode(code);
        newChannelVulnerability.setName(code);
        channelVulnerabilityDao.saveOrUpdate(newChannelVulnerability);
        return newChannelVulnerability;
    }

    /*
     * These methods help you deal with zip files. unpackZipStream() parses your inputStream
     * and stores it in zipFile, and then you can access file from it with the correct path
     * using this method.
     * TODO take these methods out
     */
    protected InputStream getFileFromZip(String fileName) {
        if (zipFile == null || fileName == null || fileName.trim().equals("")) {
            throw new ScanFileUnavailableException("zipFile was null or fileName died");
        }

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
        if (this.inputStream == null) {
            throw new ScanFileUnavailableException("inputStream was null.");
        }

        log.debug("Attempting to unpack the zip stream.");

        long timeStamp = new Date().getTime();

        diskZipFile = new File("temp-zip-file" + timeStamp);

        if (diskZipFile.exists()) {
            if (!diskZipFile.delete()) {
                log.error("Unable to proceed; can't write to " + diskZipFile.getAbsolutePath());
            }
        }

        ZipFile zipFile = null;
        FileOutputStream out = null;
        try {

            out = new FileOutputStream(diskZipFile);
            byte buf[] = new byte[1024];
            int len;

            while ((len = inputStream.read(buf)) > 0) {
                out.write(buf, 0, len);
            }

            zipFile = new ZipFile(diskZipFile);

            log.debug("Saved zip file to disk at " + diskZipFile.getAbsolutePath() + ". Returning zip file.");
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
     */
    protected String getNativeId(Finding finding) {
        if (finding == null || finding.getSurfaceLocation() == null) {
            return null;
        }

        String vulnName = null;
        if (finding.getChannelVulnerability() != null) {
            vulnName = finding.getChannelVulnerability().getName();
        }

        return hashFindingInfo(vulnName, finding.getSurfaceLocation().getPath(), finding
                .getSurfaceLocation().getParameter());
    }

    /**
     * This method wraps a lot of functionality that was previously seen in multiple importers
     * into one method to reduce duplication. It sets up the relationship between the subclassed
     * handler and the main importer, cleans and wraps the file in an InputSource, and parses it.
     * It relies on the fact that there is a common instance variable named saxFindingList that
     * the handlers are putting their Findings in, and the variable date that the parsers are putting
     * the date in.
     */
    @Nonnull
    protected Scan parseSAXInput(DefaultHandler handler) {
        log.debug("Starting SAX Parsing.");

        if (inputStream == null) {
            throw new IllegalStateException("InputStream was null. Can't parse SAX input. This is probably a coding error.");
        }

        saxFindingList = list();

        ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);

        Scan scan = new Scan();
        scan.setFindings(saxFindingList);
        scan.setApplicationChannel(applicationChannel);

        if (date != null && date.getTime() != null) {
            log.debug("SAX Parser found the scan date: " + date.getTime().toString());
            scan.setImportTime(date);
        } else {
            log.warn("SAX Parser did not find the date.");
        }

        if (scan.getFindings() != null && scan.getFindings().size() != 0) {
            log.debug("SAX Parsing successfully parsed " + scan.getFindings().size() +" Findings.");
        } else {
            log.warn("SAX Parsing did not find any Findings.");
        }

        if (shouldDeleteAfterParsing) {
            deleteScanFile();
        }

        return scan;
    }

    /**
     * TODO probably remove this unless default SAX parsing is insufficient for HTML
     * @param handler
     * @return
     */
    @Nonnull
    protected Scan parseHTMLInput(DefaultHandler handler) {
        log.debug("Starting HTML Parsing.");

        if (inputStream == null) {
            throw new IllegalStateException("InputStream was null. Can't parse HTML input. This is probably a coding error.");
        }

        saxFindingList = list();

        //ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);

        Scan scan = new Scan();
        scan.setFindings(saxFindingList);
        scan.setApplicationChannel(applicationChannel);

        if (date != null && date.getTime() != null) {
            log.debug("SAX Parser found the scan date: " + date.getTime().toString());
            scan.setImportTime(date);
        } else {
            log.warn("SAX Parser did not find the date.");
        }

        if (scan.getFindings() != null && scan.getFindings().size() != 0) {
            log.debug("SAX Parsing successfully parsed " + scan.getFindings().size() +" Findings.");
        } else {
            log.warn("SAX Parsing did not find any Findings.");
        }

        if (shouldDeleteAfterParsing) {
            deleteScanFile();
        }

        return scan;
    }

    /**
     * This method wraps a lot of functionality that was previously seen in multiple importers
     * into one method to reduce duplication. It sets up the relationship between the subclassed
     * handler and the main importer, cleans and wraps the file in an InputSource, and parses it.
     * It relies on the fact that there is a common instance variable named saxFindingList that
     * the handlers are putting their Findings in, and the variable date that the parsers are putting
     * the date in.
     */
    @Nonnull
    protected ScanCheckResultBean testSAXInput(DefaultHandler handler) {
        log.debug("Starting SAX Test.");

        if (channelTypeDao == null) {
            log.error("Spring configuration didn't have an entry for ChannelTypeDao.");
            return new ScanCheckResultBean(ScanImportStatus.CONFIGURATION_ERROR);
        }

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
     */
    @Nonnull
    protected ScanImportStatus checkTestDate() {
        if (applicationChannel == null || testDate == null) {
            return ScanImportStatus.OTHER_ERROR;
        }

        List<Scan> scanList = applicationChannel.getScanList();

        if (scanList != null) {
            for (Scan scan : scanList) {
                if (scan != null && scan.getImportTime() != null) {
                    int result = scan.getImportTime().compareTo(testDate);
                    if (result == 0) {
                        return ScanImportStatus.DUPLICATE_ERROR;
                    } else if (result > 0) {
                        return ScanImportStatus.OLD_SCAN_ERROR;
                    }
                }
            }
        }

        return ScanImportStatus.SUCCESSFUL_SCAN;
    }
}
