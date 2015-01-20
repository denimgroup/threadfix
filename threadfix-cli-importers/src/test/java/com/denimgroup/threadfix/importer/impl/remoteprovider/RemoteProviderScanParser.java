package com.denimgroup.threadfix.importer.impl.remoteprovider;

import org.springframework.transaction.annotation.Transactional;

/**
 * Created by mcollins on 1/5/15.
 */
public interface RemoteProviderScanParser {

    @Transactional(readOnly = false)
    public void testInner(String nativeName);

}
