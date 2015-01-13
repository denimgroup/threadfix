package com.denimgroup.threadfix.csv2ssl.parser;////////////////////////////////////////////////////////////////////////
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

import com.denimgroup.threadfix.csv2ssl.ResourceLoader;
import com.denimgroup.threadfix.csv2ssl.util.Strings;
import com.denimgroup.threadfix.csv2ssl.checker.FormatChecker;
import org.junit.Test;

import java.io.InputStreamReader;
import java.io.Reader;

/**
 * Created by mac on 12/2/14.
 */
public class BasicParserTest {

    @Test
    public void testBasicParser() {

        Reader reader = new InputStreamReader(ResourceLoader.getResource("basic.csv"));

        String output = CSVToSSVLParser.parse(reader,
                "CWE",
                "url",
                "parameter", "LongDescription", "NativeID", "Source");

        assert FormatChecker.checkFormat(output);

        System.out.println("Was valid, got: ");
        System.out.println(output);
    }

    @Test
    public void testParserWithEmptyColumn() {

        Reader reader = new InputStreamReader(ResourceLoader.getResource("emptycolumn.csv"));

        String output = CSVToSSVLParser.parse(reader, "CWE", "url", "parameter", "LongDescription", "", "NativeID", "Source");

        assert FormatChecker.checkFormat(output);

        System.out.println("Was valid, got: ");
        System.out.println(output);
    }
}
