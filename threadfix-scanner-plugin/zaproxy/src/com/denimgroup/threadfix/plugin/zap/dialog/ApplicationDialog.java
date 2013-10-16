package com.denimgroup.threadfix.plugin.zap.dialog;

import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;

import com.denimgroup.threadfix.plugin.zap.ThreadFixPropertiesManager;
import com.denimgroup.threadfix.plugin.zap.action.RestUtils;

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
        String baseResult = RestUtils.getApplications();

        Map<String, String> returnMap = new HashMap<>();

        for (String line : baseResult.split("\n")) {
            if (line != null && line.split(",").length == 2) {
                String[] parts = line.split(",");
                returnMap.put(parts[0], parts[1]);
            }
        }

        return returnMap;
    }

}
