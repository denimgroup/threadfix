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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;

import javax.annotation.Nonnull;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mac on 6/11/14.
 */
class DotNetEndpoint extends AbstractEndpoint {

    @Nonnull final String path;
    @Nonnull final String filePath;
    @Nonnull final Action action;

    public DotNetEndpoint(@Nonnull String path, @Nonnull String filePath, @Nonnull Action action) {
        this.path = path;
        this.filePath = filePath;
        this.action = action;
    }

    @Nonnull
    @Override
    public Set<String> getParameters() {
        return action.parameters;
    }

    @Nonnull
    @Override
    public Set<String> getHttpMethods() {
        return set(action.getMethod());
    }

    @Nonnull
    @Override
    public String getUrlPath() {
        return path;
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return filePath;
    }

    @Override
    public int getStartingLineNumber() {
        return action.lineNumber;
    }

    @Override
    public int getLineNumberForParameter(String parameter) {
        return -1;
    }

    @Override
    public boolean matchesLineNumber(int lineNumber) {
        return lineNumber >= action.lineNumber && lineNumber <= action.endLineNumber;
    }

    @Nonnull
    @Override
    protected List<String> getLintLine() {
        List<String> lintLines = list();

        if (!action.attributes.contains("HttpPost") && !action.attributes.contains("HttpGet")) {
            lintLines.add("No HTTP method limiting annotation ([HttpGet], [HttpPost]) found.");
        }

        if (!action.attributes.contains("ValidateAntiForgeryToken")) {
            lintLines.add("[ValidateAntiForgeryToken] missing.");
        }

        return lintLines;
    }
}
