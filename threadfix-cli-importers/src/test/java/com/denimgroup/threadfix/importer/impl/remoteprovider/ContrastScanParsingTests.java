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
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.importer.util.ThreadFixBridge;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastUtils.getMockedRemoteProvider;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.ContrastUtils.getRemoteProviderType;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mcollins on 1/6/15.
 */
@Component
public class ContrastScanParsingTests {

    @Autowired
    RemoteProviderFactory factory = null;
    @Autowired
    ThreadFixBridge bridge  = null;
    @Autowired
    ScanComparisonUtils utils = null;

    String[] appNames = {
            "c0a1a284-2c81-4b4b-b44a-52d7b8f71aae",
            "bodgeit-full",
            "testapp-full"
    };

    private RemoteProviderApplication getApplication(RemoteProviderType type, String nativeId) {
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setRemoteProviderType(type);
        application.setNativeId(nativeId);
        application.setApplicationChannel(new ApplicationChannel());
        return application;
    }

    @Transactional(readOnly = false)
    public void testInner(String nativeName) {

        assertTrue("Spring config is wrong. Factory was null", factory != null);
        assertTrue("Spring config is wrong. Bridge was null", bridge != null);

        ContrastRemoteProvider provider = getMockedRemoteProvider();

        bridge.injectDependenciesManually(provider);
        utils.performUpdateCheck();

        List<Scan> scans = provider.getScans(getApplication(getRemoteProviderType(), nativeName));

        assertFalse("Scans were null for application " + nativeName + ".", scans == null);
        assertFalse("Scans were empty.", scans.isEmpty());

        // TODO make more assertions about the contents here

        assert scans.size() == 1 : "Got " + scans.size() + " scans instead of 1 scan.";

        if (nativeName.equals(appNames[0])) {
            String path = scans.get(0).getFindings().get(0).getSurfaceLocation().getPath();
            assert path.equals("/threadfix/organizations/1/applications/1") :
                    "Path was " + path + " instead of \"/threadfix/organizations/1/applications/1\"";
        }
    }

    @Test
    @Ignore("We need to update these tests so that they work with the updated Contrast importer")
    public void testAllScans() {
        for (String application : appNames) {
            test(application);
        }
    }

    public static void test(String nativeName) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(ContrastScanParsingTests.class).testInner(nativeName);
    }

}
