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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;


/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 5/5/14
 * Time: 5:03 PM
 * To change this template use File | Settings | File Templates.
 */
@Component
public class ScannerMappingUpdater {

    private static final SanitizedLogger log = new SanitizedLogger(ScannerMappingUpdater.class);

    @Autowired
    private ScannerMappingsUpdaterService scannerMappingsUpdaterService;

    @PostConstruct
    public void update() {

        log.info("Checking if scanner mapping update is required");
        if (scannerMappingsUpdaterService.checkPluginJar().canUpdate) {
            scannerMappingsUpdaterService.updateMappings();
        }

    }

}
