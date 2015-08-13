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

import com.denimgroup.threadfix.data.dao.DefectTrackerTypeDao;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 8/13/15.
 */
@Component
public class DefectTrackerBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectTrackerBootstrapper.class);

    @Autowired
    DefectTrackerTypeDao defectTrackerTypeDao;

    // There are more than this but this is just a replacement for import.sql at this point
    public void bootstrap() {
        LOG.info("Adding initial Defect Tracker mappings");

        Map<String, String> typeClassMap = map(
                "Bugzilla", "com.denimgroup.threadfix.service.defects.BugzillaDefectTracker",
                "Microsoft TFS", "com.denimgroup.threadfix.service.defects.TFSDefectTracker",
                "JIRA", "com.denimgroup.threadfix.service.defects.JiraDefectTracker"
        );

        for (Map.Entry<String, String> entry : typeClassMap.entrySet()) {
            String name = entry.getKey();
            String className = entry.getValue();

            DefectTrackerType existingType = defectTrackerTypeDao.retrieveByName(name);

            if (existingType == null) {
                LOG.info("Saving type " + name);
                DefectTrackerType newType = new DefectTrackerType();

                newType.setName(name);
                newType.setFullClassName(className);

                defectTrackerTypeDao.saveOrUpdate(newType);
            } else {
                LOG.debug("Type " + name + " already existed.");
            }
        }
    }
}
