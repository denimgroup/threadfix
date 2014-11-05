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
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.framework.util.RegexUtils.getRegexResult;

/**
 * Created by mac on 10/28/14.
 */
public class WebFormsParameterParser implements ParameterParser {

    Pattern dotTextPattern = Pattern.compile("([a-zA-Z_][_a-zA-Z0-9]+).Text"),
            requestPattern = Pattern.compile("Request\\[\"([^\"]+)\"\\]");

    @Nullable
    @Override
    public String parse(@Nonnull EndpointQuery query) {
        String responseParameter = null;

        List<CodePoint> codePoints = query.getCodePoints();
        if (codePoints != null) {
            for (CodePoint codePoint : codePoints) {
                String maybeParameter = doRegex(codePoint);
                if (maybeParameter != null) {
                    responseParameter = maybeParameter;
                    break;
                }
            }
        }

        return responseParameter;
    }

    private String doRegex(CodePoint codePoint) {

        String line = codePoint.getLineText();

        if (line == null) {
            return null;
        }

        if (line.contains("=")) {
            line = line.substring(line.indexOf('='));
        }

        String regexResult = getRegexResult(line, dotTextPattern);

        return regexResult == null ?
                getRegexResult(line, requestPattern) :
                regexResult;
    }
}
