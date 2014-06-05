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

package com.denimgroup.threadfix.cli.util;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.commons.lang3.RandomStringUtils;

/**
 * Created by mcollins on 6/4/14.
 */
public class TestUtils {

    public static ThreadFixRestClient getConfiguredClient() {
        assert System.getProperty("REST_URL") != null : "The REST_URL system property is required to run this test.";
        assert System.getProperty("API_KEY") != null : "The API_KEY system property is required to run this test.";
        return new ThreadFixRestClientImpl(System.getProperty("REST_URL"), System.getProperty("API_KEY"));
    }

    public static String getRandomName() {
        return RandomStringUtils.random(10);
    }

    public static RestResponse<Application> createApplication() {
        ThreadFixRestClient client = getConfiguredClient();

        String teamId = JsonTestUtils.getId(client.createTeam(TestUtils.getRandomName()));

        return getConfiguredClient().createApplication(teamId, getRandomName(), "http://test");
    }


}
