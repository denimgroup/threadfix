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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkChecker;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.util.Collection;

/**
 * Created by mac on 9/4/14.
 */
public class WebFormsFrameworkChecker extends FrameworkChecker {

    private static final SanitizedLogger LOG = new SanitizedLogger(WebFormsFrameworkChecker.class);

    @Nonnull
    @Override
    public FrameworkType check(@Nonnull ProjectDirectory directory) {
        Collection files = FileUtils.listFiles(directory.getDirectory(),
                new FileExtensionFileFilter("aspx"), TrueFileFilter.INSTANCE);

        LOG.info("Got " + files.size() + " .aspx files from the directory.");

        return files.isEmpty() ? FrameworkType.NONE : FrameworkType.DOT_NET_WEB_FORMS;
    }

}
