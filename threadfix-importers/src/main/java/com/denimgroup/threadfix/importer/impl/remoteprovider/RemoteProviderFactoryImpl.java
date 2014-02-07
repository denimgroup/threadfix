package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by mac on 2/4/14.
 */
@Service
public class RemoteProviderFactoryImpl implements RemoteProviderFactory {

    public List<RemoteProviderApplication> fetchApplications(RemoteProviderType remoteProviderType) {
        RemoteProvider provider = getProvider(remoteProviderType.getName());

        if (provider == null)
            return null;

        provider.setRemoteProviderType(remoteProviderType);
        return provider.fetchApplications();
    }

    public RemoteProvider getProvider(String providerType) {
        if (providerType == null) {
            return null;
        }

        RemoteProvider remoteProvider = null;

        ScannerType type = ScannerType.getScannerType(providerType);

        if (type == ScannerType.QUALYSGUARD_WAS) {
            remoteProvider = new QualysRemoteProvider();
        } else if (type == ScannerType.SENTINEL) {
            remoteProvider = new WhiteHatRemoteProvider();
        } else if (type == ScannerType.VERACODE) {
            remoteProvider = new VeracodeRemoteProvider();
        }

        return remoteProvider;
    }

    /**
     * This method takes a remoteProviderApplication and does the rest of the work of getting
     * a scan file from the remote provider in question.
     * @param remoteProviderApplication
     * @return
     */
    public List<Scan> fetchScans(RemoteProviderApplication remoteProviderApplication) {
        if (remoteProviderApplication == null ||
                remoteProviderApplication.getRemoteProviderType() == null) {
            return null;
        }

        RemoteProvider provider = getProvider(remoteProviderApplication.getRemoteProviderType().getName());

        if (provider == null)
            return null;

        List<Scan> scanList = provider.getScans(remoteProviderApplication);

        if (remoteProviderApplication.getApplicationChannel() != null) {
            if (remoteProviderApplication.getApplicationChannel().getScanCounter() == null) {
                remoteProviderApplication.getApplicationChannel().setScanCounter(1);
            } else {
                remoteProviderApplication.getApplicationChannel().setScanCounter(
                        remoteProviderApplication.getApplicationChannel().getScanCounter() + 1);
            }
        }

        return scanList;
    }


}
