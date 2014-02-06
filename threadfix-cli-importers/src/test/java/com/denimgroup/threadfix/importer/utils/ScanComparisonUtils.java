package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

import static junit.framework.Assert.assertTrue;

/**
 * Created by mac on 2/6/14.
 */
public class ScanComparisonUtils {

    // Will throw errors if something is not found.
    public static void compare(String[][] array, Scan actual) {
        SimpleScan expected = SimpleScan.fromStringArray(array);

        for (SimpleFinding simpleFinding : expected) {
            boolean foundOne = false;

            for (Finding finding : actual) {
                if (simpleFinding.matches(finding)) {
                    foundOne = true;
                }
            }

            assertTrue("Didn't find match.", foundOne);
        }
    }
}
