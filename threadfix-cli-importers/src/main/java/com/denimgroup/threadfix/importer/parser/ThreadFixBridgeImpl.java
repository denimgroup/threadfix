package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.lang.reflect.Field;

@Service
public class ThreadFixBridgeImpl implements ThreadFixBridge {

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

        return importer.checkFile();
    }

    @Transactional
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

    @NotNull
    public ChannelImporter getImporter(ScannerType type) {

        ApplicationChannel channel = new ApplicationChannel();
        channel.setChannelType(new ChannelType());
        channel.getChannelType().setName(type.getFullName());

        ChannelImporter importer = factory.getChannelImporter(channel);

        if (importer == null) {
            throw new IllegalArgumentException("The supplied ScannerType should produce a " +
                    "valid ChannelImporter implementation. Fix the code.");
        }

        // We have to inject dependencies in right now
        // TODO fix this, it's dumb. Maybe move DAO impls into entities package?

        try {

            Field field = AbstractChannelImporter.class.getDeclaredField("channelVulnerabilityDao");
            field.setAccessible(true);
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

        return importer;
    }


}
