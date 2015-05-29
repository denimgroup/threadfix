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
package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.util.RegexUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by sgerick on 5/13/2015.
 */
public class RailsParameterParser implements ParameterParser {

    private static final Pattern PARAM_PATTERN = Pattern.compile("params\\[:([^]]+)\\]");

    /**
     * Return the parameter based on the data flow elements
     *
     * @param query
     */
    @Nullable
    @Override
    public String parse(@Nonnull EndpointQuery query) {
        String parameter = null;

        List<CodePoint> codePoints = query.getCodePoints();
        if (codePoints != null && !codePoints.isEmpty()) {
            for (CodePoint codePoint : codePoints) {
                String lineText = codePoint.getLineText();
                if (lineText.contains("params[:")) {
                    parameter = RegexUtils.getRegexResult(lineText, PARAM_PATTERN);
                    break;
                }
            }
        }


        if (parameter == null)
            parameter = query.getParameter();

        return parameter;
    }
}
