////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.bootstrap;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.SeverityMap;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 8/13/15.
 */
@Component
public class ScannerSeverityMappingsBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScannerSeverityMappingsBootstrapper.class);

    @Autowired
    ChannelSeverityDao channelSeverityDao;
    @Autowired
    GenericSeverityDao genericSeverityDao;
    @Autowired
    ChannelTypeDao channelTypeDao;

    @Transactional
    public void bootstrap() {
        LOG.info("Setting initial mappings for scanner severities to ThreadFix severities.");

        long start = System.currentTimeMillis();

        Map<String, GenericSeverity> genericSeverityMap = map();
        for (String name : GenericSeverity.NUMERIC_MAP.keySet()) {
            GenericSeverity severity = genericSeverityDao.retrieveByName(name);

            if (severity == null) {
                throw new IllegalStateException("Unable to find generic severity " + name);
            }

            genericSeverityMap.put(name, severity);
        }

        for (Map.Entry<String, List<String[]>> entry : getMappingsMap().entrySet()) {
            String scanner = entry.getKey();
            List<String[]> mappings = entry.getValue();

            ChannelType channelType = channelTypeDao.retrieveByName(scanner);

            if (channelType == null) {
                throw new IllegalStateException("No scanner entry found for " + scanner);
            }

            for (String[] mapping : mappings) {
                String code = mapping[0];
                String genericSeverityCode = mapping[1];

                ChannelSeverity channelSeverity = channelSeverityDao.retrieveByCode(channelType, code);
                if (channelSeverity == null) {
                    throw new IllegalStateException("Unable to find severity " + code + " for scanner " + scanner);
                }

                GenericSeverity genericSeverity = genericSeverityMap.get(genericSeverityCode);
                if (genericSeverity == null) {
                    throw new IllegalStateException("No Generic Severity entry found for " + genericSeverityCode);
                }

                if (channelSeverity.getSeverityMap() == null) {
                    SeverityMap severityMap = new SeverityMap();

                    severityMap.setChannelSeverity(channelSeverity);
                    severityMap.setGenericSeverity(genericSeverity);

                    channelSeverity.setSeverityMap(severityMap);

                    channelSeverityDao.saveOrUpdate(channelSeverity);
                }
            }
        }

        LOG.info("Took " + (System.currentTimeMillis() - start) + " ms total.");
    }

    private Map<String, List<String[]>> getMappingsMap() {
        return map("Fortify 360", list(
                        new String[] { "4.0", "High" },
                        new String[] { "3.0", "Medium" },
                        new String[] { "2.0", "Info" },
                        new String[] { "Critical", "Critical" },
                        new String[] { "High", "High" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "Low", "Low" }
                ),
                "Microsoft CAT.NET", list(
                        new String[] { "Critical", "Critical" },
                        new String[] { "High", "High" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "Low", "Low" }
                ),
                "IBM Rational AppScan", list(
                        new String[] { "High", "Critical" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "Low", "Low" },
                        new String[] { "Informational", "Info" },
                        new String[] { "Information", "Info" }
                ),
                "IBM Rational AppScan Source Edition", list(
                        new String[] { "1", "High" },
                        new String[] { "2", "Medium" },
                        new String[] { "3", "Low" },
                        new String[] { "0", "High" }
                ),
                "Skipfish", list(
                        new String[] { "1", "Low" },
                        new String[] { "2", "Medium" },
                        new String[] { "3", "High" },
                        new String[] { "4", "Critical" }
                ),
                "w3af", list(
                        new String[] { "Medium", "Medium" },
                        new String[] { "High", "High" },
                        new String[] { "Low", "Low" },
                        new String[] { "Info", "Info" }
                ),
                "WebInspect", list(
                        new String[] { "0", "Info" },
                        new String[] { "1", "Low" },
                        new String[] { "2", "Medium" },
                        new String[] { "3", "High" },
                        new String[] { "4", "Critical" }
                ),
                "Burp Suite", list(
                        new String[] { "Information", "Info" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "High", "High" },
                        new String[] { "Low", "Low" }
                ),
                "Mavituna Security Netsparker", list(
                        new String[] { "Information", "Info" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "Important", "High" },
                        new String[] { "Low", "Low" },
                        new String[] { "Critical", "Critical" }
                ),
                "WhiteHat Sentinel", list(
                        new String[] { "5", "Critical" },
                        new String[] { "4", "High" },
                        new String[] { "3", "Medium" },
                        new String[] { "2", "Medium" },
                        new String[] { "1", "Low" }
                ),
                "QualysGuard WAS", list(
                        new String[] { "5", "Critical" },
                        new String[] { "4", "High" },
                        new String[] { "3", "Medium" },
                        new String[] { "2", "Low" },
                        new String[] { "1", "Info" }
                ),
                "Manual", list(
                        new String[] { "Critical", "Critical" },
                        new String[] { "High", "High" },
                        new String[] { "Medium", "Medium" },
                        new String[] { "Low", "Low" },
                        new String[] { "Info", "Info" }
                ),
                "Veracode", list(
                        new String[] { "1", "Info" },
                        new String[] { "2", "Low" },
                        new String[] { "3", "Medium" },
                        new String[] { "4", "High" },
                        new String[] { "5", "Critical" }
                ),
                "FindBugs", list(
                        new String[] { "1", "Critical" },
                        new String[] { "2", "High" },
                        new String[] { "3", "Medium" },
                        new String[] { "4", "Low" },
                        new String[] { "5", "Info" }
                ),
                "OWASP Zed Attack Proxy", list(
                        new String[] { "1", "Low" },
                        new String[] { "2", "Medium" },
                        new String[] { "3", "High" }
                ),
                "Arachni", list(
                        new String[] { "INFORMATIONAL", "Info" },
                        new String[] { "LOW", "Low" },
                        new String[] { "MEDIUM", "High" },
                        new String[] { "HIGH", "Critical" }
                ),
                "Nessus", list(
                        new String[] { "3", "Critical" },
                        new String[] { "2", "Medium" },
                        new String[] { "1", "Low" }
                ),
                "Acunetix WVS", list(
                        new String[] { "medium", "Medium" },
                        new String[] { "high", "Critical" },
                        new String[] { "info", "Info" },
                        new String[] { "low", "Low" }
                ),
                "Brakeman", list(
                        new String[] { "3", "Medium" },
                        new String[] { "4", "High" },
                        new String[] { "1", "Info" },
                        new String[] { "2", "Low" },
                        new String[] { "5", "Critical" }
                ),
                "NTO Spider", list(
                        new String[] { "4-High", "Critical" },
                        new String[] { "3-Med", "High" },
                        new String[] { "2-Low", "Medium" },
                        new String[] { "1-Info", "Low" },
                        new String[] { "0-Safe", "Info" },
                        new String[] { "1-Informational", "Low" },
                        new String[] { "3-Medium", "High" }
                ));
    }


}
