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

package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.cli.ScanParser;
import com.denimgroup.threadfix.importer.cli.ScanSerializer;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static junit.framework.Assert.assertTrue;

@Component
public class ScanComparisonUtils {

    @Autowired
    ScanParser scanParser;

    @Autowired
    ScannerMappingsUpdaterService mappingsUpdaterService;

    private boolean needsUpdating = true;

    public static void compare(String[][] array, String filePath) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(ScanComparisonUtils.class).compareInternal(array, filePath);
    }

    @Transactional(readOnly = false)
    public void compareInternal(String[][] array, String filePath) {
        if (needsUpdating) {
            try {
                mappingsUpdaterService.updateMappings(SpringConfiguration.getContext());
                System.out.println("Updated mappings.");
                needsUpdating = false;
            } catch (Exception e) { // this isn't production code, and I'm rethrowing as RuntimeException
                throw new IllegalStateException("Encountered exception while updating channel vulns. Fix it.", e);
            }
        }
        compare(array, scanParser.getScan(filePath));
    }

    // Will throw errors if something is not found. Also requires a hibernate session.
    private void compare(String[][] array, Scan actual) {
        SimpleScan expected = SimpleScan.fromStringArray(array);

        List<SimpleFinding> findingList = list();
        Set<String> mappingErrors = set();

        for (SimpleFinding simpleFinding : expected) {
            boolean foundOne = false;

            for (Finding finding : actual) {
                try {
                    if (simpleFinding.matches(finding)) {
                        foundOne = true;
                    }
                } catch (ScannerMappingsIncompleteException e) {
                    mappingErrors.add(e.getMessage());
                }
            }

            if (!foundOne) {
                findingList.add(simpleFinding);
            }
        }

        assertTrue("We don't allow mapping errors. Specifically: " + mappingErrors, mappingErrors.isEmpty());

        if (!findingList.isEmpty()) {
            System.out.println("\nMissing mappings for:");
            for (SimpleFinding finding : findingList) {
                System.out.println(finding);
            }

            System.out.println("\nHere's the data we received:");
            System.out.println(ScanSerializer.toCSVString(actual));
        }

        assertTrue("Didn't find match for " + findingList.size() + " finding(s)", findingList.isEmpty());
    }
}
