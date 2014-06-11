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
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.WhiteHatMockHttpUtils;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 6/3/14.
 */
@Component
public class WhiteHatScanParsingTests {

    @Autowired
    RemoteProviderFactory factory = null;
    @Autowired
    ThreadFixBridge bridge = null;

    private RemoteProviderApplication getApplication(String key, String nativeId) {
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setNativeId(nativeId);
        RemoteProviderType type = new RemoteProviderType();
        type.setApiKey(key);
        application.setRemoteProviderType(type);
        return application;
    }

    public static void test(String nativeId, int[] expected) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(WhiteHatScanParsingTests.class).testInner(nativeId, expected);
    }

    @Transactional(readOnly = false)
    public void testInner(String nativeId, int[] expected) {

        assertTrue("Spring config is wrong. Factory was null", factory != null);
        assertTrue("Spring config is wrong. Bridge was null", bridge != null);

        WhiteHatRemoteProvider provider = new WhiteHatRemoteProvider();
        bridge.injectDependenciesManually(provider);

        provider.utils = new WhiteHatMockHttpUtils();

        RemoteProviderType type = new RemoteProviderType();
        type.setApiKey(WhiteHatMockHttpUtils.GOOD_API_KEY);

        provider.setRemoteProviderType(type);

        List<Scan> scans = provider.getScans(getApplication(WhiteHatMockHttpUtils.GOOD_API_KEY, nativeId));

        assertFalse("Scans were null.", scans == null);
        assertFalse("Scans were empty.", scans.isEmpty());

        // TODO make more assertions about the contents here
    }

    @Test
    public void testDemoSiteBE() {
        test("Demo Site BE", new int[] { 5, 16 });
    }

    @Test
    public void testDemoSitePE() {
        test("Demo Site PE", new int[] { 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 5, 6, 6, 7, 7, 7, 7, 7, 7, 9, 14 });
    }

    @Test
    public void testDemoSitePL() {
        test("Demo Site PL", new int[] { 51, 54, 60 });
    }

    @Test
    public void testDemoSiteSE() {
        test("Demo Site SE", new int[] { 2 });
    }

}
