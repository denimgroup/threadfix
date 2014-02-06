////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public class ConfigurationUtils {

	private static Logger log = Logger.getLogger(ConfigurationUtils.class);

    @NotNull
    public static String[] ZAP_FILES = new String[]{"zap.bat", "zap.sh"};
    @NotNull
    public static String[] ACUNETIX_FILES = new String[]{"wvs_console.exe"};
    @NotNull
    public static String[] APP_SCAN_FILES = new String[]{"AppScanCMD.exe"};

    /**
	 * Read all the scanner has been set up in scanagent properties file
	 */
	@NotNull
    public static List<Scanner> readAllScanners() {
		log.info("Start reading all scanner type");
		List<Scanner> scanners = new ArrayList<>();

        for (ScannerType type : ScannerType.values()) {
            Scanner scanner = Scanner.getScannerFromConfiguration(type);

            if (scanner != null) {
                scanners.add(scanner);
            }
        }

		log.info("Number of scanners available: " + scanners.size());
		return scanners;
	}

}
