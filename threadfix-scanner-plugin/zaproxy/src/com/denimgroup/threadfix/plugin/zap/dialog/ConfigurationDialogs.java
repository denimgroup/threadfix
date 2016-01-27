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

package com.denimgroup.threadfix.plugin.zap.dialog;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;

public class ConfigurationDialogs {

    public static enum DialogMode {
        THREADFIX_APPLICATION, SOURCE;
    }
	
	private static final Logger logger = Logger.getLogger(ConfigurationDialogs.class);

	private ConfigurationDialogs() {}
	
	public static boolean show(ViewDelegate view, DialogMode mode) {
        if (mode == DialogMode.THREADFIX_APPLICATION) {
            logger.info("About to show dialog.");

            boolean shouldContinue = ParametersDialog.show(view);

            if (shouldContinue) {
                logger.info("Got url and key settings. About to show Application selection.");

                shouldContinue = ApplicationDialog.show(view);
            }

            return shouldContinue;
        } else if (mode == DialogMode.SOURCE) {
            logger.info("About to show dialog.");

            boolean shouldContinue = SourceDialog.show(view);

            return shouldContinue;
        } else {
            return false;
        }
	}
}
