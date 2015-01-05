package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.ContrastMockHttpUtils;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider.*;

/**
 * Created by mcollins on 1/5/15.
 */
public class ContrastApplicationParsingTests {

    @Test
    public void testAppsGoodAuthentication() {
        ContrastRemoteProvider provider = new ContrastRemoteProvider();

        RemoteProviderType type = new RemoteProviderType();

        type.setAuthField(USERNAME, ContrastMockHttpUtils.GOOD_USERNAME);
        type.setAuthField(API_KEY, ContrastMockHttpUtils.GOOD_API_KEY);
        type.setAuthField(SERVICE_KEY, ContrastMockHttpUtils.GOOD_SERVICE_KEY);

        provider.setRemoteProviderType(type);
        provider.httpUtils = new ContrastMockHttpUtils();

        List<RemoteProviderApplication> remoteProviderApplications = provider.fetchApplications();

        assert remoteProviderApplications != null : "List of returned applications was null.";
        assert remoteProviderApplications.size() == 1 : "Size was " + remoteProviderApplications.size() + " instead of 1.";

        String expectedId = "c0a1a284-2c81-4b4b-b44a-52d7b8f71aae";
        String actualId = remoteProviderApplications.get(0).getNativeId();
        assert actualId.equals(expectedId) : actualId + " (id) didn't match " + expectedId;

        String expectedName = "threadfix";
        String actualName = remoteProviderApplications.get(0).getNativeName();
        assert actualName.equals(expectedName) : actualName + " (name) didn't match " + expectedId;

    }


}
