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

package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.importer.loader.AnnotationKeyGenerator;
import com.denimgroup.threadfix.importer.loader.ImplementationLoader;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ChannelImporterFactoryImpl implements ChannelImporterFactory {

    ImplementationLoader<ScanImporter, ChannelImporter> loader = null;

    @Override
    @Transactional
    public ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

        if (applicationChannel == null || applicationChannel.getChannelType() == null
                || applicationChannel.getChannelType().getName() == null
                || applicationChannel.getChannelType().getName().trim().equals("")) {
            return null;
        }

        if (loader == null) {
            init();
            assert loader != null : "Initialization failed.";
        }

        String scannerName = applicationChannel.getChannelType().getName();

        ChannelImporter importer = loader.getImplementation(scannerName);

        importer.setChannel(applicationChannel);

        return importer;
    }

    private void init() {

        loader = new ImplementationLoader<>(ScanImporter.class,
                ChannelImporter.class,
                "com.denimgroup.threadfix.importer.impl.upload",
                new AnnotationKeyGenerator<ScanImporter>() {
            @Override
            public String getKey(ScanImporter annotation) {
                return annotation.scannerName();
            }
        });
    }
}
