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

package com.denimgroup.threadfix.service.scannermapping;

import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Service;


/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 5/5/14
 * Time: 5:03 PM
 * To change this template use File | Settings | File Templates.
 */
@Service
public class ScannerMappingUpdater implements ApplicationContextAware {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScannerMappingUpdater.class);

    @Autowired
    private ScannerMappingsUpdaterService scannerMappingsUpdaterService;
    @Autowired
    private GenericVulnerabilityService genericVulnerabilityService;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {

        LOG.info("Checking if scanner mapping update is required");
        boolean canUpdate = scannerMappingsUpdaterService.checkPluginJar(applicationContext).canUpdate;
        boolean hasGenericVulns =
                genericVulnerabilityService.loadAll() != null &&
                        genericVulnerabilityService.loadAll().size() > 0;

        if (canUpdate && hasGenericVulns) {
            LOG.info("Updating mappings.");
            scannerMappingsUpdaterService.updateMappings(applicationContext);
        } else if (!canUpdate) {
            LOG.info("Scanner mappings are up-to-date, continuing");
        } else {
            LOG.info("No generic vulnerabilities found, skipping updates for now.");
        }
    }
}
