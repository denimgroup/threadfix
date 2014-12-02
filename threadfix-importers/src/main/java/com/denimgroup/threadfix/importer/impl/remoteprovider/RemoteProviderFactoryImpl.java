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

package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.importer.loader.AnnotationKeyGenerator;
import com.denimgroup.threadfix.importer.loader.ImplementationLoader;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by mac on 2/4/14.
 */
@Service
public class RemoteProviderFactoryImpl implements RemoteProviderFactory {

    @Override
    public List<RemoteProviderApplication> fetchApplications(RemoteProviderType remoteProviderType) {
        AbstractRemoteProvider provider = getProvider(remoteProviderType);

        if (provider == null) {
            return null;
        }

        return provider.fetchApplications();
    }

    private AbstractRemoteProvider getProvider(RemoteProviderType remoteProviderType) {
        if (remoteProviderType == null) {
            assert false : "Got null remote provider type.";
            return null;
        }

        if (loader == null) {
            init();
            assert loader != null : "Initialization failed.";
        }

        AbstractRemoteProvider implementation = loader.getImplementation(remoteProviderType.getName());

        if (implementation == null) {
            throw new IllegalArgumentException("No implementation found for " + remoteProviderType.getName());
        }

        implementation.setRemoteProviderType(remoteProviderType);

        return implementation;
    }

    ImplementationLoader<RemoteProvider, AbstractRemoteProvider> loader = null;

    private void init() {

        loader = new ImplementationLoader<>(RemoteProvider.class,
                AbstractRemoteProvider.class,
                "com.denimgroup.threadfix.importer.impl.remoteprovider",
                new AnnotationKeyGenerator<RemoteProvider>() {
                    @Override
                    public String getKey(RemoteProvider annotation) {
                        return annotation.name();
                    }
                });
    }

    /**
     * This method takes a remoteProviderApplication and does the rest of the work of getting
     * a scan file from the remote provider in question.
     * @param remoteProviderApplication
     * @return
     */
    @Override
    public List<Scan> fetchScans(RemoteProviderApplication remoteProviderApplication) {
        if (remoteProviderApplication == null ||
                remoteProviderApplication.getRemoteProviderType() == null) {
            return null;
        }

        AbstractRemoteProvider provider = getProvider(remoteProviderApplication.getRemoteProviderType());

        if (provider == null) {
            return null;
        }

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
