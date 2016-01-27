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

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.ContrastMockHttpUtils;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastRemoteProvider.*;

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
