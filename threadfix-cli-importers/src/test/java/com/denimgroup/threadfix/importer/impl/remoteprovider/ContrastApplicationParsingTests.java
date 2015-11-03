package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import org.junit.Ignore;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastUtils.getMockedRemoteProvider;

/**
 * Created by mcollins on 1/5/15.
 */
public class ContrastApplicationParsingTests {

    @Ignore // we have to update this to handle the current V2 API. Task filed as DGTF-2270
    @Test
    public void testAppsGoodAuthentication() {
        ContrastRemoteProvider provider = getMockedRemoteProvider();

        List<RemoteProviderApplication> remoteProviderApplications = provider.fetchApplications();

        assert remoteProviderApplications != null : "List of returned applications was null.";
        assert remoteProviderApplications.size() == 3 : "Size was " + remoteProviderApplications.size() + " instead of 3.";

        String expectedId = "c0a1a284-2c81-4b4b-b44a-52d7b8f71aae";
        String actualId = remoteProviderApplications.get(0).getNativeId();
        assert actualId.equals(expectedId) : actualId + " (id) didn't match " + expectedId;

        String expectedName = "threadfix";
        String actualName = remoteProviderApplications.get(0).getNativeName();
        assert actualName.equals(expectedName) : actualName + " (name) didn't match " + expectedId;
    }


}
