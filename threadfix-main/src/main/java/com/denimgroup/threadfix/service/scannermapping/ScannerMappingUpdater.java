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

package com.denimgroup.threadfix.service.scannermapping;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.*;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Service;

import java.util.List;


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
    @Autowired
    private DefaultConfigService defaultConfigService;
    @Autowired
    private TagService tagService;
    @Autowired
    private ChannelTypeService channelTypeService;
    @Autowired
    private RemoteProviderTypeService remoteProviderTypeService;
    @Autowired
    private BootstrapService bootstrapService;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {

        LOG.info("Checking if scanner mapping update is required");
        boolean canUpdate = scannerMappingsUpdaterService.checkPluginJar(applicationContext).canUpdate;
        boolean hasGenericVulns =
                genericVulnerabilityService.loadAll() != null &&
                        genericVulnerabilityService.loadAll().size() > 0;

        if (!hasGenericVulns) {
            bootstrapService.bootstrap();
        }

        if (canUpdate && hasGenericVulns) {
            LOG.info("Updating mappings.");
            scannerMappingsUpdaterService.updateMappings(applicationContext);
        } else if (!canUpdate) {
            LOG.info("Scanner mappings are up-to-date, continuing");
        } else {
            LOG.info("No generic vulnerabilities found, skipping updates for now.");
        }

        updateTags();
        updateChannelTypeNames();
    }

    private void updateChannelTypeNames() {
        LOG.info("Checking if we need to update channel type names.");
        DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();
        if (defaultConfiguration.getChannelTypeUpdatedDate() != null &&
                defaultConfiguration.getChannelTypeUpdatedDate().equals(ScannerType.getEnumUpdatedDate())) {
            LOG.info("No, we do not need to update channel type names.");
        } else {
            LOG.info("About to update channel type names.");
            for (ScannerType scannerType: ScannerType.values()) {
                if (!scannerType.getDisplayName().equals(scannerType.getOldName())) {
                    ChannelType channelType = channelTypeService.loadChannel(scannerType.getOldName());
                    if (channelType != null) {
                        LOG.info("Updating channel " + scannerType.getOldName() + " to " + scannerType.getDisplayName());
                        channelType.setName(scannerType.getDisplayName());
                        channelTypeService.storeChannel(channelType);
                    }

                    RemoteProviderType remoteProviderType = remoteProviderTypeService.load(scannerType.getOldName());
                    if (remoteProviderType != null) {
                        LOG.info("Updating remote provider type " + scannerType.getOldName() + " to " + scannerType.getDisplayName());
                        remoteProviderType.setName(scannerType.getDisplayName());
                        remoteProviderTypeService.store(remoteProviderType);
                    }
                }
            }
            defaultConfiguration.setChannelTypeUpdatedDate(ScannerType.getEnumUpdatedDate());
            defaultConfigService.saveConfiguration(defaultConfiguration);
            LOG.info("Finished updating channel type names.");
        }

    }

    private void updateTags() {

        LOG.info("Checking if we need to split tags to comment and application tags.");
        DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();
        if (defaultConfiguration.getHasTagCommentUpdates() == null || !defaultConfiguration.getHasTagCommentUpdates()) {
            tagService.copyAppTagsToCommentTags();
            tagService.changeTagInVulnComments();

            defaultConfiguration.setHasTagCommentUpdates(true);
            defaultConfigService.saveConfiguration(defaultConfiguration);
        } else {
            // If we need to update from Boolean TagForComment to TagType enum
            List<Tag> tagList = tagService.loadAll();
            if (tagList == null) {
                LOG.info("There is no tags in system.");
                return;
            }
            boolean needUpdate = false;
            for (Tag tag: tagList) {
                needUpdate = (tag.getType() == null) ? true : false;
                break;
            }
            if (needUpdate) {
                tagService.updateTagTypes();
            }

        }
    }
}
