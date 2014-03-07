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

package com.denimgroup.threadfix.importer.update;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.importer.util.ResourceUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
class ScannerMappingsUpdaterServiceImpl implements ScannerMappingsUpdaterService {

    private ChannelVulnerabilityDao channelVulnerabilityDao;
    private GenericVulnerabilityDao genericVulnerabilityDao;
    private ChannelTypeDao channelTypeDao;
    private DefaultConfigurationDao defaultConfigurationDao;
    private ChannelSeverityDao channelSeverityDao;
    private GenericSeverityDao genericSeverityDao;

    private static final String
            CSV_SPLIT_CHARACTER = ",",
            DATE_PATTERN = "MM/dd/yyyy hh:mm:ss";

    @Autowired
    public ScannerMappingsUpdaterServiceImpl(ChannelVulnerabilityDao channelVulnerabilityDao,
                                           ChannelTypeDao channelTypeDao,
                                           GenericVulnerabilityDao genericVulnerabilityDao,
                                           DefaultConfigurationDao defaultConfigurationDao,
                                           ChannelSeverityDao channelSeverityDao,
                                           GenericSeverityDao genericSeverityDao) {
        this.genericVulnerabilityDao = genericVulnerabilityDao;
        this.defaultConfigurationDao = defaultConfigurationDao;
        this.channelTypeDao = channelTypeDao;
        this.channelSeverityDao = channelSeverityDao;
        this.genericSeverityDao = genericSeverityDao;
        this.channelVulnerabilityDao = channelVulnerabilityDao;
    }

    private final SanitizedLogger log = new SanitizedLogger(ScannerMappingsUpdaterServiceImpl.class);

    /**
     * Add/Update ChannelVulnerabilities and their VulnerabilityMaps from reading csv file.
     * @return
     * @throws IOException
     * @throws URISyntaxException
     */
    @Override
    public List<String[]> updateChannelVulnerabilities() throws IOException, URISyntaxException {
        List<String[]> resultList = updateAllScanners();

        updateUpdatedDate();

        return resultList;
    }

    @Override
    public List<String> getSupportedScanners() {
        List<String> scanners = new ArrayList<>();

        ScannerType[] importers = ScannerType.values();

        if (importers != null) {
            for (ScannerType importer : importers) {
                scanners.add(importer.getFullName());
            }
        }

        Collections.sort(scanners);

        return scanners;
    }

    private DefaultConfiguration getDefaultConfiguration() {
        List<DefaultConfiguration> configurationList = defaultConfigurationDao.retrieveAll();
        DefaultConfiguration config;
        if (configurationList.size() == 0) {
            config = DefaultConfiguration.getInitialConfig();
        } else {
            config = configurationList.get(0);
        }

        return config;
    }

    private void updateUpdatedDate() {
        DefaultConfiguration config = getDefaultConfiguration();

        config.setLastScannerMappingsUpdate(getPluginTimestamp());

        defaultConfigurationDao.saveOrUpdate(config);
    }

    private List<String[]> updateAllScanners() {

        List<String[]> scannerResults = new ArrayList<>();

        for (ScannerType type : ScannerType.values()) {

            String filePath = "/mappings/" + type.getShortName() + ".csv";

            try (InputStream scannerStream = ResourceUtils.getResourceAsStream(filePath)) {

                if (scannerStream != null) {
                    log.info("Updating file " + filePath);
                    String[] scannerUpdateResult = updateScanner(scannerStream);
                    if (scannerUpdateResult != null) {
                        scannerResults.add(scannerUpdateResult);
                    }
                }
            } catch (IOException e) {
                log.error("Encountered IOException while trying to read the mappings file for " + type);
            }
        }

        return scannerResults;
    }

    enum State { TYPE, VULNS, SEVERITIES, NONE }

    private String[] updateScanner(InputStream is) {
        try {
            if (is != null) {
                State state = State.NONE;

                try (BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
                    String line = "";

                    int vulnsNo = 0;
                    int sevsNo = 0;

                    ChannelType channelType = null;
                    while ((line = br.readLine()) != null) {
                        if (line.startsWith("type.info")) {
                            state = State.TYPE;
                        } else if (line.startsWith("type.vulnerabilities")) {
                            state = State.VULNS;
                        } else if (line.startsWith("type.severities")) {
                            state = State.SEVERITIES;
                        } else {
                            if (state == State.TYPE) {
                                channelType = updateChannelTypeInfo(line);
                                if (channelType == null)
                                    log.warn("Was unable to update Channel Type info for " + line);
                            } else if (state == State.VULNS) {
                                if (channelType != null) {
                                    if (!updateChannelVuln(channelType, line))
                                        log.warn("Was unable to add " + line);
                                    else vulnsNo++;
                                }
                            } else if (state == State.SEVERITIES) {
                                if (channelType != null) {
                                    if (!updateChannelSeverity(channelType, line))
                                        log.warn("Was unable to add " + line);
                                    else sevsNo++;
                                }
                            }
                        }
                    }
                    if (channelType != null) {
                        log.info("Number of vulnerabilites added for " + channelType.getName() + ": " + vulnsNo);
                        log.info("Number of severities added for " + channelType.getName() + ": " + sevsNo);
                        return new String[]{channelType.getName(), String.valueOf(vulnsNo), String.valueOf(sevsNo)};
                    }
                }
            }
        } catch (IOException e) {
            log.error("IOException thrown while attempting to search csv file.", e);
        }
        return null;
    }

    private boolean updateChannelVuln(ChannelType channelType, String line) {
        // use comma as separator
        String[] elements = line.split(CSV_SPLIT_CHARACTER);
        if (elements.length < 3)
            return false;

        boolean changed = false;

        String cvName = elements[0];
        String cvCode = elements[1];
        String genericId = elements[2];

        ChannelVulnerability channelVulnerability = channelVulnerabilityDao.retrieveByCode(channelType, cvCode);

        Integer genericIdInt = IntegerUtils.getIntegerOrNull(genericId);

        if (genericIdInt == null) {
            log.warn("Failed to parse generic ID " + genericId);
        } else {
            GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveById(genericIdInt);

            if (genericVulnerability == null) {
                log.warn("Unable to find Generic Vulnerability for GenericId " + genericId);
                changed = false;
            } else {
                if (channelVulnerability != null) {
                    // Update
                    changed = updateChannelVulnerability(channelVulnerability, cvName, genericVulnerability);
                } else {
                    createNewChannelVulnerability(cvCode, cvName, genericVulnerability, channelType);
                    changed = true;
                }
            }
        }

        return changed;
    }

    private boolean updateChannelVulnerability(ChannelVulnerability channelVulnerability,
                                               String channelVulnerabilityName,
                                               GenericVulnerability genericVulnerability) {
        boolean changed = false;

        if (!channelVulnerability.getName().equalsIgnoreCase(channelVulnerabilityName)) {
            channelVulnerability.setName(channelVulnerabilityName);
            changed = true;
        }
        if (channelVulnerability.getGenericVulnerability() == null ||
                channelVulnerability.getGenericVulnerability().getId().equals(genericVulnerability.getId())) {

            if (channelVulnerability.getGenericVulnerability() != null) {
                for (VulnerabilityMap map: channelVulnerability.getVulnerabilityMaps()) {
                    map.setChannelVulnerability(null);
                }
            }

            VulnerabilityMap map = new VulnerabilityMap();
            map.setMappable(true);
            map.setChannelVulnerability(channelVulnerability);
            map.setGenericVulnerability(genericVulnerability);
            channelVulnerability.setVulnerabilityMaps(Arrays.asList(map));
            channelVulnerabilityDao.saveOrUpdate(channelVulnerability);
            changed = true;
        }

        return changed;
    }

    private void createNewChannelVulnerability(String channelVulnerabilityCode,
                                               String channelVulnerabilityName,
                                               GenericVulnerability genericVulnerability,
                                               ChannelType channelType) {
        ChannelVulnerability channelVulnerability = new ChannelVulnerability();
        channelVulnerability.setCode(channelVulnerabilityCode);
        channelVulnerability.setName(channelVulnerabilityName);
        channelVulnerability.setChannelType(channelType);

        VulnerabilityMap map = new VulnerabilityMap();
        map.setMappable(true);
        map.setChannelVulnerability(channelVulnerability);
        map.setGenericVulnerability(genericVulnerability);
        channelVulnerability.setVulnerabilityMaps(Arrays.asList(map));
        channelVulnerabilityDao.saveOrUpdate(channelVulnerability);
    }

    private boolean updateChannelSeverity(ChannelType channelType, String line) {
        // use comma as separator
        String[] elements = line.split(CSV_SPLIT_CHARACTER);
        if (elements.length < 4)
            return false;

        String csName = elements[0];
        String csCode = elements[1];
        String csNumericValue = elements[2];
        String genericSeverityId = elements[3];
        ChannelSeverity cs = channelSeverityDao.retrieveByCode(channelType,csCode);

        try {
            if (cs == null) {
                cs = new ChannelSeverity();
                cs.setCode(csCode);
            }
            cs.setName(csName);
            cs.setChannelType(channelType);
            cs.setNumericValue(Integer.valueOf(csNumericValue));
            GenericSeverity gs = genericSeverityDao.retrieveByIntValue(Integer.valueOf(genericSeverityId));
            if (gs == null) {
                log.warn("Unable to find Generic Severity for SeverityId " + genericSeverityId);
                return false;
            }
            SeverityMap map = cs.getSeverityMap();
            if (map == null)
                map = new SeverityMap();
            map.setChannelSeverity(cs);
            map.setGenericSeverity(gs);
            cs.setSeverityMap(map);
            channelSeverityDao.saveOrUpdate(cs);
            return true;
        } catch (NumberFormatException e) {
            log.warn("Numberic Value  " + csNumericValue + " or " + genericSeverityId + " is not a number");
        }

        return false;
    }


    private ChannelType updateChannelTypeInfo(String line) {

        ChannelType channelType = null;
        // use comma as separator
        String[] elements = line.split(CSV_SPLIT_CHARACTER);
        if (elements.length > 0) {

            String name = elements[0];
            channelType = channelTypeDao.retrieveByName(name);

            if (channelType == null) {
                if (elements.length < 4) {
                    log.error("Channel type information has " + elements.length + " sections instead of 4.");

                } else {
                    log.info("Creating new Channel Type " + name);
                    channelType = new ChannelType();
                    channelType.setName(name);
                    channelType.setUrl(elements[1]);
                    channelType.setVersion(elements[2]);
                    channelType.setExportInfo(elements[3]);

                    channelTypeDao.saveOrUpdate(channelType);
                }
            }
        }

        return channelType;
    }

    @Override
    public ScanPluginCheckBean checkPluginJar() {
        DefaultConfiguration configuration = getDefaultConfiguration();

        if (configuration != null && configuration.getLastScannerMappingsUpdate() != null) {

            Calendar databaseDate = configuration.getLastScannerMappingsUpdate();
            Calendar pluginDate = getPluginTimestamp();

            if (pluginDate != null && databaseDate != null && !pluginDate.after(databaseDate)) {
                return new ScanPluginCheckBean(false, databaseDate, pluginDate);
            } else {
                return new ScanPluginCheckBean(true, databaseDate, pluginDate);
            }
        } else  {
            return new ScanPluginCheckBean(true, null, null);
        }
    }

    private Calendar getPluginTimestamp() {
        Calendar returnDate = null;

        try (InputStream versionFileStream = ResourceUtils.getResourceAsStream("/mappings/version.txt")) {

            String result = IOUtils.toString(versionFileStream);

            if (result != null && !result.trim().isEmpty()) {
                returnDate = getCalendarFromString(result.trim());
            }
        } catch (IOException e) {
            log.info("IOException thrown while attempting to read version file.", e);
        }

        return returnDate;
    }

    private Calendar getCalendarFromString(String dateString) {

        Date date = null;
        try {
            date = new SimpleDateFormat(DATE_PATTERN, Locale.US).parse(dateString);
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
}
