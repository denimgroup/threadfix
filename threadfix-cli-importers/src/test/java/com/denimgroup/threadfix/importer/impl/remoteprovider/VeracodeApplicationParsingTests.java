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

import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.VeracodeMockHttpUtils;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 6/3/14.
 */
public class VeracodeApplicationParsingTests {

    public static AbstractRemoteProvider getVeracodeImporterWithMock(String username, String password) {
        VeracodeRemoteProvider provider = new VeracodeRemoteProvider();

        provider.utils = new VeracodeMockHttpUtils();

        RemoteProviderType type = new RemoteProviderType();
        type.setUsername(username);
        type.setPassword(password);

        provider.setRemoteProviderType(type);

        return provider;
    }

    @Test
    public void readAppsAuthenticated() {
        AbstractRemoteProvider provider = getVeracodeImporterWithMock(VeracodeMockHttpUtils.GOOD_USERNAME,
                VeracodeMockHttpUtils.GOOD_PASSWORD);

        List<RemoteProviderApplication> applications = provider.fetchApplications();

        assertTrue("Applications were null.", applications != null);
        assertFalse("Applications were empty.", applications.isEmpty());
    }

    @Test
    public void readAppsUnauthenticated() {
        AbstractRemoteProvider provider = getVeracodeImporterWithMock(VeracodeMockHttpUtils.BAD_USERNAME,
                VeracodeMockHttpUtils.BAD_PASSWORD);

        List<RemoteProviderApplication> applications = provider.fetchApplications();

        assertTrue("Applications weren't null.", applications == null);
    }

}
