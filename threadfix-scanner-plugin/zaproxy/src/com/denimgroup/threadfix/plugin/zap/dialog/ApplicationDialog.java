package com.denimgroup.threadfix.plugin.zap.dialog;

import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import com.denimgroup.threadfix.plugin.zap.rest.Application;
import com.denimgroup.threadfix.plugin.zap.rest.ApplicationsRestResponse;
import com.denimgroup.threadfix.plugin.zap.rest.RestResponse;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ThreadFixPropertiesManager;

import com.denimgroup.threadfix.plugin.zap.rest.RestUtils;

public class ApplicationDialog {

    private static final Logger logger = Logger.getLogger(ApplicationDialog.class);

    public static boolean show(ViewDelegate view) {

        Map<String, String> applicationMap = getApplicationMap();
        
        String resultId = null;

        Object[] possibilities = applicationMap.keySet().toArray();
        
        if (possibilities.length != 0) {
	        ImageIcon icon = new ImageIcon("images/middle.gif");
	        Object idResult = JOptionPane.showInputDialog(
	                view.getMainFrame(),
	                "Pick an Application",
	                "Pick an Application",
	                JOptionPane.PLAIN_MESSAGE,
	                icon,
	                possibilities,
	                ThreadFixPropertiesManager.getAppId());
	        
	        if (idResult != null && !idResult.toString().trim().isEmpty() ) {
	        	// Got a valid result
	        	resultId = applicationMap.get(idResult);
	        	logger.info("Got application ID: " + resultId);
	        	ThreadFixPropertiesManager.setAppId(resultId);
	        }
        } else {
        	view.showWarningDialog("Failed while trying to get a list of applications from ThreadFix.");
        }
        
        return resultId != null;
    }

    public static Map<String, String> getApplicationMap() {
        RestResponse baseResult = RestUtils.getApplications();

        Map<String, String> returnMap = new HashMap<>();

        if (baseResult != null && baseResult.wasSuccessful()) {
            ApplicationsRestResponse appsResponse = new ApplicationsRestResponse(baseResult);

            for (Application app : appsResponse.getApplications()) {
                if (app != null && app.getCombinedName() != null && app.getId() != null) {
                    returnMap.put(app.getCombinedName(), app.getId());
                }
            }
        }

        return returnMap;
    }

}
