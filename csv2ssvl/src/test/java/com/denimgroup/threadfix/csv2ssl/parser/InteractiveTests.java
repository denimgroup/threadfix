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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.ResourceLoader;
import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import org.junit.Before;
import org.junit.Test;

import static com.denimgroup.threadfix.csv2ssl.DialogUtils.testDialog;

/**
 * Created by mcollins on 1/21/15.
 */
public class InteractiveTests {

    @Before
    public void init() {
        Configuration.reset();
    }

    @Test
    public void testBasicDialog() {

        // define inputs
        String dialog =
                "n\n" +
                "n\n" +
                "CWE,url,Parameter,LongDescription,NativeID,Source\n" +
                "y\n" +
                "n\n" +
                ResourceLoader.getFilePath("basic.csv") + "\n" +
                ResourceLoader.getFilePath("out.ssvl") + "\n";

        testDialog(dialog);
    }
    @Test
    public void testBasicDialogWithFileName() {

        // define inputs
        String dialog =
                "n\n" +
                "n\n" +
                "CWE,url,Parameter,LongDescription,NativeID,Source,SourceFileName\n" +
                "y\n" +
                "n\n" +
                ResourceLoader.getFilePath("filename.csv") + "\n" +
                ResourceLoader.getFilePath("out.ssvl") + "\n";

        String result = testDialog(dialog);

        System.out.println(result);

        assert result.contains("SourceFileName=\"testfile.jsp\"") : "Got " + result;
    }

    @Test
    public void testWithColumnConfiguration() {

        // define inputs
        String dialog =
                "n\n" +
                "n\n" +
                "1,2,3,4,5,6\n" +
                "y\n" +
                "y\n" +
                "skip\n" +
                "1\n" +
                "6\n" +
                "2\n" +
                "3\n" +
                "5\n" +
                "4\n" +
                "skip\n" +
                "skip\n" +
                "skip\n" +
                "skip\n" +
                "n\n" +
                ResourceLoader.getFilePath("basic.csv") + "\n" +
                "stdout\n";

        testDialog(dialog);
    }

    @Test
    public void testWithHeaderInFile() {

        String dialog =
                "n\n" +
                "y\n" +
                ResourceLoader.getFilePath("withHeaderLine.csv") + "\n" +
                "y\n" +
                "n\n" +
                "stdout\n";

        testDialog(dialog);
    }

    @Test
    public void testBadLineEndings() {

        String dialog =
                "n\n" +
                "y\n" +
                ResourceLoader.getFilePath("windows-line-endings.csv") + "\n" +
                "y\n" +
                "n\n" +
                "stdout\n";

        testDialog(dialog);
    }

    @Test
    public void testWithDifferentHeadersInFile() {
        String dialog =
                "n\n" +
                "y\n" +
                ResourceLoader.getFilePath("withDifferentHeaderLine.csv") + "\n" +
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
                "skip\n" +
                "n\n" +
                "stdout\n";

        testDialog(dialog);
    }

    @Test
    public void testConfigurationPrompt() {
        String dialog =
                "y\n" +
                ResourceLoader.getFilePath("fromJunit.properties") + "\n" +
                ResourceLoader.getFilePath("withDifferentHeaderLine.csv") + "\n";

        System.out.println(dialog);

        testDialog(dialog);
    }

    @Test
    public void testWithQuotes() {
        String dialog =
                "y\n" +
                "\"" + ResourceLoader.getFilePath("fromJunit.properties") + "\"\n" +
                "\"" + ResourceLoader.getFilePath("withDifferentHeaderLine.csv") + "\"\n";

        System.out.println(dialog);

        testDialog(dialog);
    }

}
