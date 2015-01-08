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
