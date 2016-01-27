////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.util;

import com.denimgroup.threadfix.util.SimilarityCalculator;
import org.junit.Test;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.util.SimilarityCalculator.findMostSimilarFilePath;

/**
 * Created by mcollins on 8/25/15.
 */
public class SimilarityCalculatorTests {

    @Test
    public void basicTest() {
        compare("/this/is/a/test/path/File.java",
                "/this/is/another/test/path/File.java",
                3);
    }

    @Test
    public void testLongerPath1() {
        compare("/this/is/a/longer/path/to/this/is/another/test/path/File.java",
                "/this/is/another/test/path/File.java",
                6);
    }

    @Test
    public void testLongerPath2() {
        compare("/this/is/another/test/path/File.java",
                "/this/is/a/longer/path/to/this/is/another/test/path/File.java",
                6);
    }

    @Test
    public void testSingleMatch() {
        compare("/this/is/one/path/File.java",
                "heres/another/one/File.java",
                1);
    }

    @Test
    public void testZeroLength() {
        compare("These/are/different/Files.java",
                "This/is/another/Thing.java",
                0);
    }

    private void compare(String filePath1, String filePath2, int expected) {
        int similarity = SimilarityCalculator.calculateSimilarity(
                filePath1,
                filePath2);

        assert similarity == expected : "Expected " + expected + ", got " + similarity;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                  Find single path
    //////////////////////////////////////////////////////////////////////////////////////////

    @Test
    public void test() {
        String match = findMostSimilarFilePath("/this/is/a/file/path/File.java",
                list(
                        "test/Junk.java", "web.xml",
                        "/File.java",
                        "path/File.java",
                        "/file/path/2/File.java",
                        "/is/a/file/path/File.java",
                        "/other/junk/File.java",
                        "/this/is/a/File.java"
                ));

        assert "/is/a/file/path/File.java".equals(match) : "Got " + match + " instead of " +
                "/is/a/file/path/File.java";
    }

}
