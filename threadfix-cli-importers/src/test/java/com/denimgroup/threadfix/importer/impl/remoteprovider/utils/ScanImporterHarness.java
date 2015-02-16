package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.importer.impl.remoteprovider.RemoteProviderScanParser;

/**
 * Created by mcollins on 1/5/15.
 */
public class ScanImporterHarness {

    private ScanImporterHarness(){}

    public static <T extends RemoteProviderScanParser> void test(Class<T> myClass, String nativeName) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(myClass).testInner(nativeName);
    }

}
