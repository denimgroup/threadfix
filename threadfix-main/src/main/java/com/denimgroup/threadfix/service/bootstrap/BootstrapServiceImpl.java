////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.BootstrapService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static java.lang.System.currentTimeMillis;

/**
 * Created by mcollins on 8/12/15.
 */
@Component
public class BootstrapServiceImpl implements BootstrapService {

    private static final SanitizedLogger LOG = new SanitizedLogger(BootstrapServiceImpl.class);

    @Autowired
    GenericSeverityBootstrapper genericSeverityBootstrapper;
    @Autowired
    ScannerTypeBootstrapper scannerTypeBootstrapper;
    @Autowired
    ApplicationCriticalityBootstrapper applicationCriticalityBootstrapper;
    @Autowired
    WafBootstrapper wafBootstrapper;
    @Autowired
    DefectTrackerBootstrapper defectTrackerBootstrapper;
    @Autowired
    ScannerSeveritiesBootstrapper scannerSeveritiesBootstrapper;
    @Autowired
    ScannerSeverityMappingsBootstrapper scannerSeverityMappingsBootstrapper;
    @Autowired
    GenericVulnerabilityBootstrapper genericVulnerabilityBootstrapper;
    @Autowired
    ScannerVulnerabilityTypeBootstrapper scannerVulnerabilityTypeBootstrapper;
    @Autowired
    UserRoleBootstrapper userRoleBootstrapper;
    @Autowired
    RemoteProviderBootstrapper remoteProviderBootstrapper;

    @Override
    public void bootstrap() {
        LOG.info("Bootstrapping.");

        long startTime = currentTimeMillis();
        try {

            userRoleBootstrapper.bootstrap();

            genericSeverityBootstrapper.bootstrap();
            remoteProviderBootstrapper.bootstrap();
            scannerTypeBootstrapper.bootstrap();
            applicationCriticalityBootstrapper.bootstrap();
            wafBootstrapper.bootstrap();
            defectTrackerBootstrapper.bootstrap();

            scannerSeveritiesBootstrapper.bootstrap();
            scannerSeverityMappingsBootstrapper.bootstrap();

            genericVulnerabilityBootstrapper.bootstrap();

            scannerVulnerabilityTypeBootstrapper.bootstrap();
        } finally {
            LOG.info("Bootstrapping took " + (currentTimeMillis() - startTime) + " ms.");
        }
    }
}
