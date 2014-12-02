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
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.WhiteHatMockHttpUtils;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 6/3/14.
 */
public class WhiteHatApplicationParsingTests {

    public static String[] appIds = new String[] { "Demo Site BE", "Demo Site PE", "Demo Site PL", "Demo Site SE" };

    public static AbstractRemoteProvider getWhiteHatImporterWithMock(String apiKey) {
        WhiteHatRemoteProvider provider = new WhiteHatRemoteProvider();

        provider.utils = new WhiteHatMockHttpUtils();

        RemoteProviderType type = new RemoteProviderType();
        type.setApiKey(apiKey);

        provider.setRemoteProviderType(type);

        return provider;
    }

    @Test
    public void getApplicationsValidCredentials() {
        AbstractRemoteProvider provider = getWhiteHatImporterWithMock(WhiteHatMockHttpUtils.GOOD_API_KEY);

        List<RemoteProviderApplication> applications = provider.fetchApplications();

        assertTrue("Got " + applications.size() + " apps instead of 4.",
                applications.size() == 4);

        for (String string : appIds) {
            boolean valid = false;
            for (RemoteProviderApplication application : applications) {
                if (string.equals(application.getNativeName())) {
                    valid = true;
                }
            }
            assertTrue("Didn't find " + string, valid);
        }
    }

    @Test
    public void getApplicationsInvalidCredentials() {
        AbstractRemoteProvider provider = getWhiteHatImporterWithMock(WhiteHatMockHttpUtils.BAD_API_KEY);

        List<RemoteProviderApplication> applications = provider.fetchApplications();

        assertTrue("Applications were supposed to be null.", applications == null);
    }
}
