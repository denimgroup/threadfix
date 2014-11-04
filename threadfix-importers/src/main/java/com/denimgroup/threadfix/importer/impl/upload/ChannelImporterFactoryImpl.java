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
import com.denimgroup.threadfix.importer.loader.ScannerTypeLoader;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

@Service
class ChannelImporterFactoryImpl implements ChannelImporterFactory {

    private static final SanitizedLogger LOG = new SanitizedLogger(ChannelImporterFactoryImpl.class);

    Map<String, Class<?>> classMap = newMap();

    boolean initialized = false;

    @Override
    @Transactional
    public ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

        if (applicationChannel == null || applicationChannel.getChannelType() == null
                || applicationChannel.getChannelType().getName() == null
                || applicationChannel.getChannelType().getName().trim().equals("")) {
            return null;
        }

        if (!initialized) {
            init();
            assert initialized : "Initialization failed.";
        }

        String scannerName = applicationChannel.getChannelType().getName();

        Class<?> channelImporterClass = classMap.get(scannerName);

        ChannelImporter importer;

        try {
            assert channelImporterClass != null : "Got null class for key " + scannerName;

            Constructor<?>[] constructors = channelImporterClass.getConstructors();

            assert constructors.length == 1 : "Got " + constructors.length + " constructors.";

            Object maybeImporter = constructors[0].newInstance();

            if (maybeImporter instanceof ChannelImporter) {
                importer = (ChannelImporter) maybeImporter;
            } else {
                throw new IllegalStateException(channelImporterClass +
                        " didn't implement ChannelImporter. Fix your code and try again.");
            }

        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        }

        importer.setChannel(applicationChannel);

        return importer;
    }

    private void init() {
        Map<ScanImporter, Class<?>> map = ScannerTypeLoader.getMap();

        for (Map.Entry<ScanImporter, Class<?>> entry : map.entrySet()) {
            classMap.put(entry.getKey().scannerName(), entry.getValue());
        }

        initialized = true;
    }
}
