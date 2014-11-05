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
import java.util.List;

/**
 * Created by mac on 9/4/14.
 */
public class AspxParserTests {

    @Test
    public void testBasicNameParsing() {
        AspxParser parser = AspxParser.parse(ResourceManager.getDotNetWebFormsFile("WebForm1.aspx"));

        assert parser.aspName.equals("WebForm1.aspx") :
                "Got " + parser.aspName + " instead of WebForm1.aspx.";
    }

    @Test
    public void testBasicIdParsing() {
        AspxParser parser = AspxParser.parse(ResourceManager.getDotNetWebFormsFile("WebForm1.aspx"));

        assert parser.ids.contains("ddl") :
                "Parser didn't find ddl: " + parser;
        assert parser.ids.contains("newitem") :
                "Parser didn't find newitem: " + parser;
        assert parser.ids.contains("test") :
                "Parser didn't find test: " + parser;
    }

    @Test
    public void testRequestParsingInAspx() {
        File dotNetWebFormsFile = ResourceManager.getDotNetWebFormsFile("Message.aspx");

        assert dotNetWebFormsFile.exists() && dotNetWebFormsFile.isFile() :
                "Message.aspx was not found. Path should have been " + dotNetWebFormsFile.getAbsolutePath();

        AspxParser parser = AspxParser.parse(dotNetWebFormsFile);

        List<String> strings = parser.parameters;

        assert strings != null : "Parameters were null";
        assert strings.contains("Msg") :
                "Aspx.cs parser failed to get Msg: " + parser;
    }

    @Test
    public void testChangePassword() {
        File dotNetWebFormsFile = ResourceManager.getDotNetWebFormsFile("ChangePassword.aspx");

        assert dotNetWebFormsFile.isFile() :
                "ChangePassword.aspx was not a file. Path should have been " + dotNetWebFormsFile.getAbsolutePath();

        AspxParser parser = AspxParser.parse(dotNetWebFormsFile);

        assertVariablePresence(parser, "txtPassword1", "txtPassword2");
    }

    @Test
    public void testProductDetails() {
        File dotNetWebFormsFile = ResourceManager.getDotNetWebFormsFile("ProductDetails.aspx");

        assert dotNetWebFormsFile.isFile() :
                "ChangePassword.aspx was not a file. Path should have been " + dotNetWebFormsFile.getAbsolutePath();

        AspxParser parser = AspxParser.parse(dotNetWebFormsFile);

        assertVariablePresence(parser, "txtComment", "txtEmail", "hiddenFieldProductID");
    }

    private void assertVariablePresence(AspxParser parser, String... variables) {
        List<String> strings = parser.ids;

        assert strings != null : "IDs were null";

        for (String variable : variables) {
            assert strings.contains(variable) :
                    "Aspx.cs parser failed to get " + variable + ": " + parser;
        }
    }


}
