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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetEndpoint extends AbstractEndpoint {

    final String path;
    final String filePath;
    final int lineNumber;

    public DotNetEndpoint(String path, String filePath, int lineNumber) {
        this.path = path;
        this.filePath = filePath;
        this.lineNumber = lineNumber;
    }

    @Nonnull
    @Override
    public Set<String> getParameters() {
        return new HashSet<>();
    }

    @Nonnull
    @Override
    public Set<String> getHttpMethods() {
        return new HashSet<>(Arrays.asList("GET"));
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
        return lineNumber;
    }

    @Override
    public int getLineNumberForParameter(String parameter) {
        return -1;
    }

    @Override
    public boolean matchesLineNumber(int lineNumber) {
        return lineNumber == this.lineNumber;
    }
}
