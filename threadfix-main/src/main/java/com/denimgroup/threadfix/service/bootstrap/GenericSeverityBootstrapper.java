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

import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.GenericSeverityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static java.lang.System.currentTimeMillis;

/**
 * Created by mcollins on 8/12/15.
 */
@Component
public class GenericSeverityBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(GenericSeverityBootstrapper.class);

    @Autowired
    GenericSeverityService genericSeverityService;

    @Transactional(readOnly = false)
    public void bootstrap() {

        LOG.info("Adding generic severities.");

        long start = currentTimeMillis();

        for (Map.Entry<String, Integer> entry : GenericSeverity.NUMERIC_MAP.entrySet()) {
            String name = entry.getKey();
            Integer intValue = entry.getValue();

            GenericSeverity databaseSeverity = genericSeverityService.loadByName(name);

            if (databaseSeverity != null) {
                LOG.debug("Severity " + name + " was already present in the database. Skipping.");
                continue;
            }

            GenericSeverity severity = new GenericSeverity();
            severity.setName(name);
            severity.setIntValue(intValue);

            genericSeverityService.saveOrUpdate(severity);
        }

        LOG.info("Generic Severities took " + (currentTimeMillis() - start) + " ms.");
    }


}
