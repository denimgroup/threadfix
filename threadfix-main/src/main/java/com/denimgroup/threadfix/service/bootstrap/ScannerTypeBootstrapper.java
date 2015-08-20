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

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import static com.denimgroup.threadfix.service.bootstrap.ResourceLineIterable.getIterator;

/**
 * Created by mcollins on 8/12/15.
 */
@Component
public class ScannerTypeBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScannerTypeBootstrapper.class);

    @Autowired
    ChannelTypeDao channelTypeDao;

    @Transactional
    public void bootstrap() {
        LOG.info("Creating initial scanner types.");

        int lineNumber = 0;

        for (String line : getIterator("bootstrap/scanners/base.csv")) {
            String[] split = line.split("\\|");

            lineNumber++;

            if (split.length != 4) {
                throw new IllegalStateException(
                        "Got " + split.length + " sections instead of 4 in bootstrap/scanners/base.csv at line " + lineNumber);
            }

            String scannerName = split[0],
                    url = split[1],
                    version = split[2],
                    exportInfo = split[3];

            ChannelType channelType = channelTypeDao.retrieveByName(scannerName);
            if (channelType != null) {
                LOG.debug("Channel type was already created for " + scannerName);
                continue;
            }

            ChannelType newChannelType = new ChannelType();
            newChannelType.setName(scannerName);
            newChannelType.setUrl(url);
            newChannelType.setVersion(version);
            newChannelType.setExportInfo(exportInfo);

            LOG.info("Adding type " + scannerName);

            channelTypeDao.saveOrUpdate(newChannelType);

        }
    }

}
