////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer.check;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.importer.exception.ScanFileUnavailableException;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.importer.util.ThreadFixBridge;
import com.denimgroup.threadfix.importer.utils.FolderMappings;
import org.junit.Test;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Component
public class FormatCheckTests {

    StringBuilder builder;

    Calendar minusOneYear = Calendar.getInstance();
    { // subtract a year
        minusOneYear.set(Calendar.YEAR, minusOneYear.get(Calendar.YEAR) - 1);
    }

    @Test
    public void testFalseNegatives() {
        ThreadFixBridge threadFixBridge = getThreadFixBridge();

        builder = new StringBuilder();

        for (Map.Entry<ScannerType, Collection<String>> entry : FolderMappings.getEntries()) {
            Calendar mostRecent = null;
            for (String file : entry.getValue()) {
                try {
                    ScanCheckResultBean returnBean =
                            threadFixBridge.testScan(entry.getKey(), new File(file));

                    assertTrue("Got null return bean while testing " + file, returnBean != null);
                    assertTrue("Response status wasn't success for file " + file + ", it was " +
                            returnBean.getScanCheckResult(),
                            returnBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN);

                    if (mostRecent == null || mostRecent.before(returnBean.getTestDate())) {
                        mostRecent = returnBean.getTestDate();
                    }
                } catch (ScanFileUnavailableException e) {
                    e.printStackTrace();
                    assertTrue("Response status wasn't success for file " + file +
                            ". Encountered ScanFileUnavailableException.", false);
                }
            }

            addToBuilder(entry.getKey(), mostRecent);
        }

        System.out.println(builder);
    }

    @Test
    public void testFalsePositives() {
        ThreadFixBridge threadFixBridge = getThreadFixBridge();

        builder = new StringBuilder();

        for (Map.Entry<ScannerType, Collection<String>> outerEntry : FolderMappings.getEntries()) {
            for (Map.Entry<ScannerType, Collection<String>> innerEntry : FolderMappings.getEntries()) {

                if (innerEntry.getKey() != outerEntry.getKey()) {

                    for (String file : innerEntry.getValue()) {
                        try {
                            ScanCheckResultBean returnBean =
                                    threadFixBridge.testScan(outerEntry.getKey(), new File(file));

                            assertTrue("Got null return bean while testing " + file, returnBean != null);
                            assertTrue("Response status was success for scanner " + outerEntry.getKey() +
                                            " and file " + file + ".",
                                    returnBean.getScanCheckResult() != ScanImportStatus.SUCCESSFUL_SCAN);

                        } catch (ScanFileUnavailableException | IllegalStateException e) {
                            // This happens sometimes if zip files can't be read properly
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private ThreadFixBridge getThreadFixBridge() {
        ThreadFixBridge threadFixBridge = SpringConfiguration.getContext().getBean(ThreadFixBridge.class);
        assertNotNull("Fix your autowiring, ThreadFixBridge instance was null.", threadFixBridge);
        return threadFixBridge;
    }

    private void addToBuilder(ScannerType type, Calendar recentDate) {
        if (recentDate == null) {
            builder.append("No date was found for scanner ")
                    .append(type)
                    .append("\n");
        } else if (recentDate.before(minusOneYear)) {
            builder.append("We only have outdated scans for ")
                    .append(type)
                    .append(". The most recent was ")
                    .append(format(recentDate))
                    .append("\n");
        } else {
            builder.append("Most recent scan for ")
                    .append(type)
                    .append(" was ")
                    .append(format(recentDate))
                    .append("\n");
        }
    }

    public String format(Calendar calendar) {
        return new SimpleDateFormat("MM/dd/yyyy").format(calendar.getTime());
    }

    /**
     * Skipfish parsing used to work but only about half the time. This should ensure that if the problem
     * exists in the code then it will fail at least one test.
     */
    @Test
    @Transactional
    public void runSkipFishLotsOfTimesToMakeSureItWorks() {

        ThreadFixBridge threadFixBridge = getThreadFixBridge();

        for (int i = 0; i < 20; i++) {
            System.out.print('.');
            for (String file : FolderMappings.getValue(ScannerType.SKIPFISH)) {
                System.out.print('-');
                ScanCheckResultBean returnBean =
                        threadFixBridge.testScan(ScannerType.SKIPFISH, new File(file));

                assertTrue("Got null return bean while testing " + file, returnBean != null);
                assertTrue("Response status wasn't success for file " + file + ", it was " +
                        returnBean.getScanCheckResult(),
                        returnBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN);

                threadFixBridge.getScan(ScannerType.SKIPFISH, new File(file));
            }
        }
    }

}
