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
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.importer.update.Updater;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.IOException;

import static com.denimgroup.threadfix.importer.update.UpdaterConstants.GENERIC_VULNS_FOLDER;

/**
 * Created by mac on 9/12/14.
 */
@Service
@MappingsUpdater
public class GenericMappingsUpdater extends SpringBeanAutowiringSupport implements Updater, Ordered {

    private static final SanitizedLogger LOG = new SanitizedLogger(GenericMappingsUpdater.class);

    @Autowired
    private GenericVulnerabilityDao     genericVulnerabilityDao;
    @Autowired
    private ChannelTypeDao              channelTypeDao;
    @Autowired
    private ChannelVulnerabilityDao     channelVulnerabilityDao;
    @Autowired
    private ChannelVulnerabilityUpdater channelVulnerabilityUpdater;

    @Override
    public int getOrder() {
        return 100;
    }

    enum State { TYPE, VULNS, SEVERITIES, NONE }

    @Override
    public void doUpdate(@Nonnull String fileName, @Nonnull BufferedReader bufferedReader) throws IOException {

        LOG.info("Updating generic vulnerabilities from file " + fileName);

        int updatedNo = 0, addedNewNo = 0;
        String updatedList = "", addedNewList = "";

        State state = State.NONE;

        assert channelTypeDao != null : "ChannelType DAO was null, fix the autowiring code.";

        ChannelType manualChannel = channelTypeDao.retrieveByName("Manual");

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            if (line.startsWith("type.info")) {
                state = State.TYPE;
            } else if (line.startsWith("type.vulnerabilities")) {
                state = State.VULNS;
            } else {
                if (state == State.VULNS) {
                    String[] elements = line.split(",");
                    if (elements.length < 2) {
                        LOG.warn("Line " + line + " information is incorrect.");
                    } else {
                        Integer genericIdInt = IntegerUtils.getIntegerOrNull(elements[0]);

                        if (genericIdInt == null) {
                            LOG.warn("Failed to parse generic ID " + elements[0]);
                        } else {

                            if (!isUpdateGenericVuln(genericIdInt, elements[1], manualChannel)) {
                                addedNewNo++;
                                addedNewList += (addedNewList.isEmpty()? "" : ", ") + genericIdInt;
                            } else {
                                updatedNo++;
                                updatedList += (updatedList.isEmpty()? "" : ", ") + genericIdInt;
                            }
                        }
                    }
                }
            }
        }
        LOG.info("Number of generic vulnerabilities added new : " + addedNewNo + ", include " + addedNewList);
        LOG.info("Number of generic vulnerabilities updated : " + updatedNo + ", include " + updatedList);
    }

    @Override
    public String getFolder() {
        return GENERIC_VULNS_FOLDER;
    }

    private boolean isUpdateGenericVuln(int genericIdInt, String genericNewName, ChannelType manualType) {

        GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveByDisplayId(genericIdInt);

        boolean isUpdate = genericVulnerability != null;
        String oldName = null;
        if (genericVulnerability == null) {
            LOG.info("Add new Generic Vulnerability with CWE Id " + genericIdInt);
            genericVulnerability = new GenericVulnerability();
            genericVulnerability.setCweId(genericIdInt);
        } else {
            LOG.info("Update Generic Vulnerability with Id " + genericIdInt);
            oldName = genericVulnerability.getName();
        }

        genericVulnerability.setName(genericNewName);
        genericVulnerabilityDao.saveOrUpdate(genericVulnerability);

        updateManualVuln(genericVulnerability,oldName, genericNewName, manualType);

        return isUpdate;
    }


    private void updateManualVuln(GenericVulnerability genericVulnerability, String oldName, String newName, ChannelType channelType) {
        if (channelType == null) return;

        ChannelVulnerability vulnerability;
        if (oldName != null) {
            LOG.info("Update Manual Vulnerability: " + oldName + " to: " + newName);
            vulnerability = channelVulnerabilityDao.retrieveByName(channelType, oldName);
            vulnerability.setCode(newName);
            vulnerability.setName(newName);
            channelVulnerabilityDao.saveOrUpdate(vulnerability);
        } else {
            LOG.info("Create new Manual Vulnerability: " + newName);
            channelVulnerabilityUpdater.createNewChannelVulnerability(newName, newName, genericVulnerability, channelType);
        }
    }
}
