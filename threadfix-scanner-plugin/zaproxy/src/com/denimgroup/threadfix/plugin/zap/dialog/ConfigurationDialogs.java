package com.denimgroup.threadfix.plugin.zap.dialog;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;

public class ConfigurationDialogs {
	
	private static final Logger logger = Logger.getLogger(ConfigurationDialogs.class);

	private ConfigurationDialogs() {}
	
	public static boolean show(ViewDelegate view) {
		logger.info("About to show dialog.");

        boolean shouldContinue = ParametersDialog.show(view);
        
        if (shouldContinue) {
            logger.info("Got url and key settings. About to show Application selection.");
	
            shouldContinue = ApplicationDialog.show(view);
        }
        
        return shouldContinue;
	}
}
