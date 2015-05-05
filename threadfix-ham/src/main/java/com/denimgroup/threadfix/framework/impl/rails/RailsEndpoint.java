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

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Set;

/**
 * Created by sgerick on 5/5/2015.
 */
public class RailsEndpoint extends AbstractEndpoint {
    @Nonnull
    @Override
    protected List<String> getLintLine() {
        return null;
    }

    @Nonnull
    @Override
    public Set<String> getParameters() {
        return null;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
    }

    @Nonnull
    @Override
    public Set<String> getHttpMethods() {
        return null;
    }

    @Nonnull
    @Override
    public String getUrlPath() {
        return null;
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return null;
    }

    @Override
    public int getStartingLineNumber() {
        return 0;
    }

    @Override
    public int getLineNumberForParameter(String parameter) {
        return 0;
    }

    @Override
    public boolean matchesLineNumber(int lineNumber) {
        return true;
    }
}
