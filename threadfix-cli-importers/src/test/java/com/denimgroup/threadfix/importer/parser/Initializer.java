package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.cli.ScanParser;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;

/**
 * Created by mac on 2/6/14.
 */
public class Initializer {

    private static ScanParser INSTANCE = null;

    public static ScanParser getScanParser() {
        if (INSTANCE == null) {
            INSTANCE = SpringConfiguration.getContext().getBean(ScanParser.class);

            if (INSTANCE == null) {
                throw new IllegalStateException("Spring was incorrectly configured. " +
                        "This won't work until it is reconfigured.");
            }
        }

        return INSTANCE;
    }


}
