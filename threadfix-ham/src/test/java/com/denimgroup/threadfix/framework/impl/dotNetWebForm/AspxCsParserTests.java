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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import java.io.File;
import java.util.Set;

/**
 * Created by mac on 9/4/14.
 */
public class AspxCsParserTests {

    @Test
    public void testNameParsing() {
        AspxCsParser csParser = AspxCsParser.parse(ResourceManager.getDotNetWebFormsFile("WebForm1.aspx.cs"));

        assert csParser.aspName.equals("WebForm1.aspx.cs") :
                "Didn't have the right name (WebForm1.aspx.cs), got " + csParser;
    }

    @Test
    public void testBasicParamParsing() {
        AspxCsParser csParser = AspxCsParser.parse(ResourceManager.getDotNetWebFormsFile("WebForm1.aspx.cs"));

        assert csParser.lineNumberToParametersMap.get(20).contains("newitem") :
                "Aspx.cs parser failed to get newitem at line 20: " + csParser;
    }

    @Test
    public void testRequestSquareBracketStyleParameters() {
        File dotNetWebFormsFile = ResourceManager.getDotNetWebFormsFile("ViewStatement.aspx.cs");

        assert dotNetWebFormsFile.exists() && dotNetWebFormsFile.isFile() :
                "ViewStatement.aspx.cs was not found. Path should have been " + dotNetWebFormsFile.getAbsolutePath();

        AspxCsParser csParser = AspxCsParser.parse(dotNetWebFormsFile);

        Set<String> strings = csParser.lineNumberToParametersMap.get(22);

        assert strings != null : "Strings were null for line 22. Map was: " + csParser.lineNumberToParametersMap;
        assert strings.contains("StatementID") :
                "Aspx.cs parser failed to get StatementID at line 22: " + csParser;
    }

}
