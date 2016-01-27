////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import org.junit.Ignore;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastUtils.getMockedRemoteProvider;

/**
 * Created by mcollins on 1/5/15.
 */
public class ContrastApplicationParsingTests {

    @Ignore("We need to update these tests so that they work with the updated Contrast importer")
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
