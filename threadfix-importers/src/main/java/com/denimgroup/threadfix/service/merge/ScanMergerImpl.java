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
package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.translator.PathGuesser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ScanMergerImpl implements ScanMerger {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScanMergerImpl.class);

    @Autowired
    private ApplicationMerger applicationMerger;
    @Autowired
    private ScanDao           scanDao;
    @Autowired
    private VulnerabilityDao  vulnerabilityDao;
    @Autowired
    private ScanCleanerUtils  scanCleanerUtils;
    @Autowired
    private PermissionsHandler permissionsHandler;

    @Override
    public void merge(Scan scan, ApplicationChannel applicationChannel) {
        merge(scan, applicationChannel, true);
    }

    @Override
    public void merge(Scan scan, ApplicationChannel applicationChannel, boolean shouldSaveScan) {

        assert applicationMerger != null : "applicationMerger was null, fix your Spring configuration.";
        assert scanDao != null : "scanDao was null, fix your Spring configuration.";

        if (scan.getFindings() != null && applicationChannel != null
                && applicationChannel.getChannelType() != null
                && applicationChannel.getChannelType().getName() != null) {
            LOG.info("The " + applicationChannel.getChannelType().getName()
                    + " import was successful" + " and found "
                    + scan.getFindings().size() + " findings.");
        }

        if (applicationChannel == null
                || applicationChannel.getApplication() == null
                || applicationChannel.getApplication().getId() == null) {
            LOG.error("An incorrectly configured application made it to processRemoteScan()");
            return;
        }

        // TODO probably make all of these autowired
        Application application = applicationChannel.getApplication();

        PathGuesser.generateGuesses(application, scan);
        ChannelMerger.channelMerge(vulnerabilityDao, scan, applicationChannel);
        applicationMerger.applicationMerge(scan, application, null);

        scan.setApplicationChannel(applicationChannel);
        scan.setApplication(applicationChannel.getApplication());

        if (scan.getNumberTotalVulnerabilities() != null
                && scan.getNumberNewVulnerabilities() != null) {
            LOG.info(applicationChannel.getChannelType().getName()
                    + " scan completed processing with "
                    + scan.getNumberTotalVulnerabilities()
                    + " total Vulnerabilities ("
                    + scan.getNumberNewVulnerabilities() + " new).");
        } else {
            LOG.info(applicationChannel.getChannelType().getName()
                    + " scan completed.");
		}

        scanCleanerUtils.clean(scan);
        if (shouldSaveScan) {
            scanDao.saveOrUpdate(scan);
            permissionsHandler.setPermissions(scan, application.getId());
        }
	}
}
