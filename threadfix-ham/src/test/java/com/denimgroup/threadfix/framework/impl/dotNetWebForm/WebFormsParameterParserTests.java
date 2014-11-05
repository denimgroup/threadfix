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

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.DefaultCodePoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 10/28/14.
 */
public class WebFormsParameterParserTests {

    EndpointQuery generateCodePoints(String... lines) {
        List<CodePoint> codePoints = list();

        for (String line : lines) {
            codePoints.add(new DefaultCodePoint("test", 1, line));
        }

        return EndpointQueryBuilder.start()
                .setCodePoints(codePoints)
                .generateQuery();
    }

    @Test
    public void testBasicDataFlow() {
        ParameterParser webFormsParser = new WebFormsParameterParser();

        EndpointQuery query = generateCodePoints(
                "string sql = @\"SELECT * FROM [User] WHERE Username = '\" + txtUsername.Text + @\"'\";",
                "sql",
                "sql",
                "SqlCommand"
        );

        String param = webFormsParser.parse(query);

        assert param != null : "Received null parameter.";
        assert param.equals("txtUsername") : "Didn't get txtUsername, got " + param;
    }

    @Test
    public void testOnlyOnLeftSideOfEquals() {
        ParameterParser webFormsParser = new WebFormsParameterParser();

        EndpointQuery query = generateCodePoints(
                "retVal = cmd.ExecuteReader();",
                "retVal",
                "ExecuteDataReader",
                "lblStateLocalTaxes.Text = String.Format(\"{0:c}\", (decimal)reader[\"StateLocalTaxes\"]);"
        );

        String param = webFormsParser.parse(query);

        assert param == null : "Didn't get null, got " + param;
    }

    @Test
    public void testOnBothSidesOfEquals() {
        ParameterParser webFormsParser = new WebFormsParameterParser();

        EndpointQuery query = generateCodePoints(
                "lblMessage.Text = \"Message sent to \" + Request[\"email\"] + \" with subject \" + txtSubject.Text + \" and content \" + txtMessage.Text;",
                "lblMessage.Text = \"Message sent to \" + Request[\"email\"] + \" with subject \" + txtSubject.Text + \" and content \" + txtMessage.Text;"
        );

        String param = webFormsParser.parse(query);

        assert param != null : "Param was null.";
        assert !param.equals("lblMessage") :
                "Got lblMessage, but was expecting something else because " +
                        "lblMessages is on the left side of the equals.";
    }

}
