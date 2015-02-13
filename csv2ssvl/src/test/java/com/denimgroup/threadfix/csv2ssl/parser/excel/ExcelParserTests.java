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
package com.denimgroup.threadfix.csv2ssl.parser.excel;

import com.denimgroup.threadfix.csv2ssl.ResourceLoader;
import org.junit.Test;

import static com.denimgroup.threadfix.csv2ssl.DialogUtils.testDialog;

/**
 * Created by mcollins on 2/12/15.
 */
public class ExcelParserTests {

    private String filePath =
            ResourceLoader.getFilePath("withDifferentHeaderLine.xlsx");

    @Test
    public void testConfigurationPrompt() {
        String dialog =
                "y\n" +
                ResourceLoader.getFilePath("fromJunit.properties") + "\n" +
                filePath + "\n";

        System.out.println(dialog);

        testDialog(dialog);
    }

    @Test
    public void testWithDifferentHeadersInFile() {
        String dialog =
                        "n\n" +
                        "y\n" +
                        filePath + "\n" +
                        "y\n" +
                        "y\n" +
                        "skip\n" +
                        "VulnType\n" +
                        "Scanner\n" +
                        "Location\n" +
                        "Injection Point\n" +
                        "ID\n" +
                        "Text\n" +
                        "skip\n" +
                        "skip\n" +
                        "skip\n" +
                        "n\n" +
                        "stdout\n";

        testDialog(dialog);
    }




}
