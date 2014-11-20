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
package com.denimgroup.threadfix.importer.update.impl;

import com.denimgroup.threadfix.annotations.MappingsUpdater;
import com.denimgroup.threadfix.data.dao.DefectTrackerTypeDao;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.importer.update.Updater;
import com.denimgroup.threadfix.importer.update.UpdaterConstants;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * Created by mac on 9/12/14.
 */
@MappingsUpdater
@Service
public class DefectTrackerUpdater extends SpringBeanAutowiringSupport implements Updater, Ordered {

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectTrackerUpdater.class);
    @Autowired
    private DefectTrackerTypeDao defectTrackerTypeDao;

    @Override
    public void doUpdate(@Nonnull String fileName, @Nonnull BufferedReader reader) throws IOException {

        LOG.info("Updating defect tracker information from file " + fileName);

        String line = reader.readLine();

        while (line != null) {

            String[] splitLine = StringUtils.split(line, ',');

            if (splitLine.length == 2) {
                DefectTrackerType type = defectTrackerTypeDao.retrieveByName(splitLine[0]);

                if (type == null) {
                    // let's create one
                    type = new DefectTrackerType();

                    type.setName(splitLine[0]);
                    type.setFullClassName(splitLine[1]);

                    defectTrackerTypeDao.saveOrUpdate(type);

                    LOG.info("Created a Defect Tracker with name " + splitLine[0]);

                } else {
                    LOG.info("Already had an entry for " + splitLine[0]);
                }

            } else {
                LOG.error("Line had " + splitLine.length + " sections instead of 2: " + line);
            }

            line = reader.readLine();
        }
    }

    @Override
    public String getFolder() {
        return UpdaterConstants.DEFECT_TRACKERS_FOLDER;
    }

    @Override
    public int getOrder() {
        return 400;
    }
}
