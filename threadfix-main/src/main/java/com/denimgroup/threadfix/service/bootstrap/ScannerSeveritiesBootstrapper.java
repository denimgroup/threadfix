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
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.util.Tuple3;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.util.Tuple3.tuple3;

/**
 * Created by mcollins on 8/13/15.
 */
@Component
public class ScannerSeveritiesBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScannerSeveritiesBootstrapper.class);

    @Autowired
    ChannelSeverityDao channelSeverityDao;
    @Autowired
    ChannelTypeDao channelTypeDao;

    @Transactional
    public void bootstrap() {
        LOG.info("Adding initial scanner severities.");

        for (Map.Entry<String, List<Tuple3<String, String, Integer>>> entry : getSeveritiesMap().entrySet()) {
            String scanner = entry.getKey();
            List<Tuple3<String, String, Integer>> severities = entry.getValue();

            ChannelType channelType = channelTypeDao.retrieveByName(scanner);

            if (channelType == null) {
                String error = "No scanner entry found in ChannelType table for " + scanner;
                LOG.error(error);
                throw new IllegalStateException(error);
            }

            for (Tuple3<String, String, Integer> severity : severities) {
                String name = severity.getFirst();
                String code = severity.getSecond();
                Integer numericValue = severity.getThird();

                LOG.debug("Adding new severity (" + code + ") for " + scanner);

                ChannelSeverity newSeverity = new ChannelSeverity();

                newSeverity.setName(name);
                newSeverity.setCode(code);
                newSeverity.setNumericValue(numericValue);
                newSeverity.setChannelType(channelType);

                channelSeverityDao.saveOrUpdate(newSeverity);
            }
        }
    }

    // having this in a method means we lazy load the memory and let it go afterwards
    // (as compared to a field or static variable)
    private Map<String, List<Tuple3<String, String, Integer>>> getSeveritiesMap() {
        return map(
                "Fortify 360", list(
                        tuple3("Hot", "4.0", 3),
                        tuple3("Warning", "3.0", 2),
                        tuple3("Info", "2.0", 1),
                        tuple3("Critical", "Critical", 4),
                        tuple3("High", "High", 3),
                        tuple3("Medium", "Medium", 2),
                        tuple3("Low", "Low", 1)
                ),
                "Microsoft CAT.NET", list(
                        tuple3("Critical", "Critical", 5),
                        tuple3("High", "High", 4),
                        tuple3("Medium", "Medium", 3),
                        tuple3("Low", "Low", 2),
                        tuple3("Info", "Info", 1)
                ),
                "IBM Rational AppScan", list(
                        tuple3("High", "High", 4),
                        tuple3("Medium", "Medium", 3),
                        tuple3("Low", "Low", 2),
                        tuple3("Informational", "Informational", 1),
                        tuple3("Information", "Information", 1)
                ),
                "IBM Rational AppScan Source Edition", list(
                        tuple3("Medium", "2", 2),
                        tuple3("Low", "3", 1),
                        tuple3("High", "1", 3),
                        tuple3("High", "0", 3)
                ),
                "Skipfish", list(
                        tuple3("0", "0", 1),
                        tuple3("1", "1", 2),
                        tuple3("2", "2", 3),
                        tuple3("3", "3", 4),
                        tuple3("4", "4", 5)
                ),
                "w3af", list(
                        tuple3("Medium", "Medium", 3),
                        tuple3("Low", "Low", 2),
                        tuple3("High", "High", 4),
                        tuple3("Info", "Info", 1)
                ),
                "WebInspect", list(
                        tuple3("0", "0", 1),
                        tuple3("1", "1", 2),
                        tuple3("2", "2", 3),
                        tuple3("3", "3", 4),
                        tuple3("4", "4", 5)
                ),
                "Veracode", list(
                        tuple3("1", "1", 1),
                        tuple3("2", "2", 2),
                        tuple3("3", "3", 3),
                        tuple3("4", "4", 4),
                        tuple3("5", "5", 5)
                ),
                "Burp Suite", list(
                        tuple3("Information", "Information", 1),
                        tuple3("Medium", "Medium", 3),
                        tuple3("High", "High", 4),
                        tuple3("Low", "Low", 2)
                ),
                "Mavituna Security Netsparker", list(
                        tuple3("Information", "Information", 1),
                        tuple3("Medium", "Medium", 3),
                        tuple3("Important", "Important", 4),
                        tuple3("Low", "Low", 2),
                        tuple3("Critical", "Critical", 5)
                ),
                "WhiteHat Sentinel", list(
                        tuple3("5", "5", 5),
                        tuple3("4", "4", 4),
                        tuple3("3", "3", 3),
                        tuple3("2", "2", 2),
                        tuple3("1", "1", 1)
                ),
                "QualysGuard WAS", list(
                        tuple3("5", "5", 5),
                        tuple3("4", "4", 4),
                        tuple3("3", "3", 3),
                        tuple3("2", "2", 2),
                        tuple3("1", "1", 1)
                ),
                "Manual", list(
                        tuple3("Critical", "Critical", 5),
                        tuple3("High", "High", 4),
                        tuple3("Medium", "Medium", 3),
                        tuple3("Low", "Low", 2),
                        tuple3("Info", "Info", 1)
                ),
                "FindBugs", list(
                        tuple3("1", "1", 1),
                        tuple3("2", "2", 2),
                        tuple3("3", "3", 3),
                        tuple3("4", "4", 4),
                        tuple3("5", "5", 5)
                ),
                "OWASP Zed Attack Proxy", list(
                        tuple3("1", "1", 1),
                        tuple3("2", "2", 2),
                        tuple3("3", "3", 3),
                        tuple3("4", "4", 4),
                        tuple3("5", "5", 5)
                ),
                "Arachni", list(
                        tuple3("INFORMATIONAL", "INFORMATIONAL", 1),
                        tuple3("LOW", "LOW", 2),
                        tuple3("MEDIUM", "MEDIUM", 3),
                        tuple3("HIGH", "HIGH", 4)
                ),
                "Nessus", list(
                        tuple3("1", "1", 1),
                        tuple3("2", "2", 2),
                        tuple3("3", "3", 3)
                ),
                "Acunetix WVS", list(
                        tuple3("medium", "medium", 3),
                        tuple3("high", "high", 4),
                        tuple3("info", "info", 1),
                        tuple3("low", "low", 2)
                ),
                "Brakeman", list(
                        tuple3("Medium", "3", 3),
                        tuple3("High", "4", 4),
                        tuple3("Info", "1", 1),
                        tuple3("Low", "2", 2),
                        tuple3("Critical", "5", 5)
                ),
                "NTO Spider", list(
                        tuple3("0-Safe", "0-Safe", 1),
                        tuple3("1-Info", "1-Info", 2),
                        tuple3("2-Low", "2-Low", 3),
                        tuple3("3-Med", "3-Med", 4),
                        tuple3("4-High", "4-High", 5),
                        tuple3("3-Medium", "3-Medium", 4),
                        tuple3("1-Informational", "1-Informational", 2)
                )
        );
    }


}
