package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class ChannelImporterFactoryImpl implements ChannelImporterFactory {

    @Override
    @Transactional
    public ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

        if (applicationChannel == null || applicationChannel.getChannelType() == null
                || applicationChannel.getChannelType().getName() == null
                || applicationChannel.getChannelType().getName().trim().equals("")) {
            return null;
        }

        ScannerType type = ScannerType.getScannerType(applicationChannel.getChannelType().getName());

        ChannelImporter channelImporter = null;

        // This is gross, but better than the now unnecessary plugin loading.
        // This also has the advantage of static type checking.
        // The compiler will let us know if we're missing a branch.
        switch (type) {
            case ACUNETIX_WVS:       channelImporter = new AcunetixChannelImporter(); break;
            case APPSCAN_DYNAMIC:    channelImporter = new AppScanWebImporter(); break;
            case APPSCAN_SOURCE:     channelImporter = new AppScanSourceChannelImporter(); break;
            case APPSCAN_ENTERPRISE: channelImporter = new AppScanEnterpriseChannelImporter(); break;
            case ARACHNI:            channelImporter = new ArachniChannelImporter(); break;
            case BRAKEMAN:           channelImporter = new BrakemanChannelImporter(); break;
            case BURPSUITE:          channelImporter = new BurpSuiteChannelImporter(); break;
            case CAT_NET:            channelImporter = new CatNetChannelImporter(); break;
            case CHECKMARX:          channelImporter = new CheckMarxChannelImporter(); break;
            case DEPENDENCY_CHECK:   channelImporter = new DependencyCheckChannelImporter(); break;
            case FINDBUGS:           channelImporter = new FindBugsChannelImporter(); break;
            case FORTIFY:            channelImporter = new FortifyChannelImporter(); break;
            case NESSUS:             channelImporter = new NessusChannelImporter(); break;
            case NTO_SPIDER:         channelImporter = new NTOSpiderChannelImporter(); break;
            case NETSPARKER:         channelImporter = new NetsparkerChannelImporter(); break;
            case SKIPFISH:           channelImporter = new SkipfishChannelImporter(); break;
            case W3AF:               channelImporter = new W3afChannelImporter(); break;
            case WEBINSPECT:         channelImporter = new WebInspectChannelImporter(); break;
            case ZAPROXY:            channelImporter = new ZaproxyChannelImporter(); break;
            case MANUAL:             channelImporter = new SSVLChannelImporter(); break;

            // these don't get anything
            case QUALYSGUARD_WAS:
            case SENTINEL:
            case VERACODE:
        }

        if (channelImporter != null) {
            channelImporter.setChannel(applicationChannel);
        }

        return channelImporter;
    }

}
