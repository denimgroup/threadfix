package com.denimgroup.threadfix.plugin.zap.dialog;

import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.remote.PluginClient;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

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
                    ZapPropertiesManager.INSTANCE.getAppId());
	        
	        if (idResult != null && !idResult.toString().trim().isEmpty() ) {
	        	// Got a valid result
	        	resultId = applicationMap.get(idResult.toString());
	        	logger.info("Got application ID: " + resultId);
	        	ZapPropertiesManager.setAppId(resultId);
	        }
        } else {
        	view.showWarningDialog("Failed while trying to get a list of applications from ThreadFix.");
        }
        
        return resultId != null;
    }

    public static Map<String, String> getApplicationMap() {
        PluginClient client = new PluginClient(ZapPropertiesManager.INSTANCE);

        Application.Info[] apps = client.getThreadFixApplications();

        Map<String, String> returnMap = new HashMap<>();

        if (apps != null) {
            for (Application.Info app : apps) {
                if (app != null && getCombinedName(app) != null && app.getApplicationId() != null) {
                    returnMap.put(getCombinedName(app), app.getApplicationId());
                }
            }
        }

        return returnMap;
    }

    private static String getCombinedName(Application.Info info) {
        return info.getOrganizationName() + "/" + info.getApplicationName();
    }

}
