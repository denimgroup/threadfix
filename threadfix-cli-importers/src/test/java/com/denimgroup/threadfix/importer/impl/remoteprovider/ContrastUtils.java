package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.ContrastMockHttpUtils;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider.API_KEY;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider.SERVICE_KEY;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider.USERNAME;

/**
 * Created by mcollins on 1/6/15.
 */
public class ContrastUtils {

    private ContrastUtils(){}

    private static RemoteProviderType type = null;

    public static RemoteProviderType getRemoteProviderType() {
        if (type == null) {
            type = new RemoteProviderType();

            type.setAuthField(USERNAME, ContrastMockHttpUtils.GOOD_USERNAME);
            type.setAuthField(API_KEY, ContrastMockHttpUtils.GOOD_API_KEY);
            type.setAuthField(SERVICE_KEY, ContrastMockHttpUtils.GOOD_SERVICE_KEY);
        }

        return type;
    }

    static ContrastRemoteProvider getMockedRemoteProvider() {
        ContrastRemoteProvider provider = new ContrastRemoteProvider();

        provider.setRemoteProviderType(getRemoteProviderType());
        provider.setChannel(new ApplicationChannel());
        provider.httpUtils = new ContrastMockHttpUtils();
        return provider;
    }
}
