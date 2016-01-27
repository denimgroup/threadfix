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
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.VeracodeMockHttpUtils;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.importer.util.ThreadFixBridge;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.denimgroup.threadfix.importer.util.SpringConfiguration.getSpringBean;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 6/3/14.
 */
@Component
public class VeracodeScanParsingTests {

    @Autowired
    RemoteProviderFactory factory = null;
    @Autowired
    ThreadFixBridge       bridge  = null;

    String[] appNames = {
            "Dynamic Sample Application", "Open SSH", "Galleon", "Apache",
            "Roller", "HSQLdb", "Bodgeit", "DVWA", "BlogEngine.NET", "Lunar Lander",
            "Metamail", "Hadoop", "WebGoat",
    };

    private RemoteProviderApplication getApplication(RemoteProviderType type, String nativeName) {
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setNativeName(nativeName);
        application.setRemoteProviderType(type);
        application.setApplicationChannel(new ApplicationChannel());
        return application;
    }

    @Transactional(readOnly = false)
    public void testInner(String nativeName) {

        assertTrue("Spring config is wrong. Factory was null", factory != null);
        assertTrue("Spring config is wrong. Bridge was null", bridge != null);

        VeracodeRemoteProvider provider = new VeracodeRemoteProvider();
        bridge.injectDependenciesManually(provider);

        provider.utils = new VeracodeMockHttpUtils();

        RemoteProviderType type = new RemoteProviderType();
        type.setUsername(VeracodeMockHttpUtils.GOOD_USERNAME);
        type.setPassword(VeracodeMockHttpUtils.GOOD_PASSWORD);

        provider.setRemoteProviderType(type);
        provider.setChannel(new ApplicationChannel());

        List<Scan> scans = provider.getScans(getApplication(type, nativeName));

        assertFalse("Scans were null for application " + nativeName + ".", scans == null);
        assertFalse("Scans were empty.", scans.isEmpty());

        // TODO make more assertions about the contents here
    }

    @Test
    public void testAllScans() {
        for (String application : appNames) {
            test(application);
        }
    }

    public static void test(String nativeName) {
        getSpringBean(VeracodeScanParsingTests.class).testInner(nativeName);
    }
}
