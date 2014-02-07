package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.cli.ScanParser;
import com.denimgroup.threadfix.importer.cli.ScanSerializer;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import static junit.framework.Assert.assertTrue;

@Component
public class ScanComparisonUtils {

    @Autowired
    ScanParser scanParser;

    public static void compare(String[][] array, String filePath) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(ScanComparisonUtils.class).compareInternal(array, filePath);
    }

    @Transactional(readOnly = true)
    public void compareInternal(String[][] array, String filePath) {
        compare(array, scanParser.getScan(filePath));
    }

    // Will throw errors if something is not found. Also requires a hibernate session.
    private void compare(String[][] array, Scan actual) {
        SimpleScan expected = SimpleScan.fromStringArray(array);

        for (SimpleFinding simpleFinding : expected) {
            boolean foundOne = false;

            for (Finding finding : actual) {
                if (simpleFinding.matches(finding)) {
                    foundOne = true;
                }
            }
            if (!foundOne) {
                System.out.println(ScanSerializer.toCSVString(actual));
            }

            assertTrue("Didn't find match for finding " + simpleFinding, foundOne);
        }
    }
}
