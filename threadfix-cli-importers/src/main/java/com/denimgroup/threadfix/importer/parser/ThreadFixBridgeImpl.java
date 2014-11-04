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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.xml.sax.SAXParseException;

import java.io.File;
import java.lang.reflect.Field;

@Service
public class ThreadFixBridgeImpl implements ThreadFixBridge {

	private static final SanitizedLogger LOG = new SanitizedLogger(ThreadFixBridgeImpl.class);

    @Autowired
    public ChannelImporterFactory factory;
    @Autowired
    public ScanTypeCalculationService scanTypeCalculationService;

    public ScannerType getType(File file) {

        if (scanTypeCalculationService == null) {
            throw new IllegalStateException("Spring is not configured correctly. Fix the code.");
        }

        return scanTypeCalculationService.getScannerType(file);
    }

    public ScanCheckResultBean testScan(ScannerType type, File inputFile) {
        ChannelImporter importer = getImporter(type);

        importer.setFileName(inputFile.getAbsolutePath());

	    try {
            return importer.checkFile();
	    } catch (RestIOException e) {
		    LOG.warn("Received exception for file " +
				    inputFile.getAbsolutePath() +
				    ", returning invalid format bean.", e);
		    return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);
	    }
    }

    @Override
    public void injectDependenciesManually(ChannelImporter importer) {
        // We have to inject dependencies in right now
        // TODO fix this, reflection = dirty. Maybe move DAO impls into entities package?

        try {

            Field field = AbstractChannelImporter.class.getDeclaredField("channelVulnerabilityDao");
            field.setAccessible(true); // this is probably not a good idea
            field.set(importer, channelVulnerabilityDao);

            field = AbstractChannelImporter.class.getDeclaredField("channelTypeDao");
            field.setAccessible(true);
            field.set(importer, channelTypeDao);

            field = AbstractChannelImporter.class.getDeclaredField("genericVulnerabilityDao");
            field.setAccessible(true);
            field.set(importer, genericVulnerabilityDao);

            field = AbstractChannelImporter.class.getDeclaredField("channelSeverityDao");
            field.setAccessible(true);
            field.set(importer, channelSeverityDao);

            if (importer instanceof AbstractChannelImporter) {
                ((AbstractChannelImporter) importer).shouldDeleteAfterParsing = false;
            } else {
                throw new IllegalStateException("All channel importers need to extend " +
                        "AbstractChannelImporter for this module to work.");
            }

        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    public Scan getScan(ScannerType type, File inputFile) {
        ChannelImporter importer = getImporter(type);

        importer.setFileName(inputFile.getAbsolutePath());

        return importer.parseInput();
    }

    @Autowired
    protected ChannelVulnerabilityDao channelVulnerabilityDao;
    @Autowired
    protected ChannelSeverityDao channelSeverityDao;
    @Autowired
    protected ChannelTypeDao channelTypeDao;
    @Autowired
    protected GenericVulnerabilityDao genericVulnerabilityDao;

    public ChannelImporter getImporter(ScannerType type) {

        ApplicationChannel channel = new ApplicationChannel();
        channel.setChannelType(new ChannelType());
        channel.getChannelType().setName(type.getDbName());

        ChannelImporter importer = factory.getChannelImporter(channel);

        if (importer == null) {
            throw new IllegalArgumentException("The supplied ScannerType should produce a " +
                    "valid ChannelImporter implementation. Fix the code.");
        }

        // We have to inject dependencies in right now
        // TODO fix this, reflection = dirty. Maybe move DAO impls into entities package?

        injectDependenciesManually(importer);

        return importer;
    }


}
