////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;

import javax.annotation.Nonnull;
import java.util.List;

/**
 * Created by sgerick on 1/6/2015.
 */
public class StrutsPathCleaner extends DefaultPathCleaner {

    public static final String JSESSIONID = ";jsessionid=";


    public StrutsPathCleaner(List<PartialMapping> partialMappings) {
        super(partialMappings);
    }

    @Override
    public String cleanDynamicPath(@Nonnull String urlPath) {
        String relativeUrlPath = super.cleanDynamicPath(urlPath);

        String escaped = relativeUrlPath;

        if (escaped.contains(JSESSIONID)) {
            escaped = escaped.substring(0, escaped.indexOf(JSESSIONID));
        }

        return escaped;
    }
}
