package com.denimgroup.threadfix.importer.check;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanImportStatus;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import com.denimgroup.threadfix.importer.utils.FolderMappings;
import org.junit.Test;
import org.springframework.stereotype.Component;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Map;

import static junit.framework.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Component
public class FormatCheckTests {

    @Test
    public void testFalseNegatives() {

        ThreadFixBridge threadFixBridge = SpringConfiguration.getContext().getBean(ThreadFixBridge.class);
        assertNotNull("Fix your autowiring, ThreadFixBridge instance was null.", threadFixBridge);


        Calendar minusOneYear = Calendar.getInstance();
        minusOneYear.set(Calendar.YEAR, minusOneYear.get(Calendar.YEAR) - 1);

        for (Map.Entry<ScannerType, Collection<String>> entry : FolderMappings.getEntries()) {
            Calendar mostRecent = null;
            for (String file : entry.getValue()) {
                ScanCheckResultBean returnBean =
                        threadFixBridge.testScan(entry.getKey(), new File(file));

                assertTrue("Got null return bean while testing " + file, returnBean != null);
                assertTrue("Response status wasn't success for file " + file + ", it was " +
                        returnBean.getScanCheckResult(), returnBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN);

                if (mostRecent == null || mostRecent.before(returnBean.getTestDate())) {
                    mostRecent = returnBean.getTestDate();
                }
            }

            if (mostRecent == null) {
                System.out.println("No date was found for scanner " + entry.getKey());
            } else if (mostRecent.before(minusOneYear)) {
                System.out.println("We only have outdated scans for " + entry.getKey() +
                        ". The most recent was " + format(mostRecent));
            } else {
                System.out.println("Most recent scan for " + entry.getKey() + " was " + format(mostRecent));
            }
        }
    }

    public String format(Calendar calendar) {
        return new SimpleDateFormat("MM/dd/yyyy").format(calendar.getTime());
    }

}
