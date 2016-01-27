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

package burp.dialog;

import burp.extention.BurpPropertiesManager;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.data.entities.Application;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class ApplicationDialog {

    public static boolean show(Component view) {
        Map<String, String> applicationMap = getApplicationMap();

        BurpPropertiesManager burpPropertiesManager = BurpPropertiesManager.getBurpPropertiesManager();
        String appId = burpPropertiesManager.getAppId();
        if ((appId != null) && !appId.trim().isEmpty() && applicationMap.containsValue(appId)) {
            return true;
        }

        String resultId = null;
        Object[] possibilities = applicationMap.keySet().toArray();

        if (possibilities.length != 0 && possibilities[0].toString().startsWith("Authentication failed")) {
            JOptionPane.showMessageDialog(view,possibilities[0].toString());
        }
        else if (possibilities.length != 0) {
	        ImageIcon icon = new ImageIcon("images/middle.gif");
	        Object idResult = JOptionPane.showInputDialog(
                    view,
                    "Pick an Application",
                    "Pick an Application",
                    JOptionPane.PLAIN_MESSAGE,
                    icon,
                    possibilities,
                    burpPropertiesManager.getAppId());
	        
	        if (idResult != null && !idResult.toString().trim().isEmpty() ) {
	        	// Got a valid result
	        	resultId = applicationMap.get(idResult);
                burpPropertiesManager.setAppId(resultId);
	        }
        } else {
            JOptionPane.showMessageDialog(view, "Failed while trying to get a list of applications from ThreadFix.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
        }
        
        return resultId != null;
    }

    public static Map<String, String> getApplicationMap() {
        Application.Info[] infos = RestUtils.getApplications();

        Map<String, String> returnMap = new HashMap<>();

        for (Application.Info info : infos) {
                returnMap.put(info.getOrganizationName() + "/" + info.getApplicationName(),
                        info.getApplicationId());
        }

        return returnMap;
    }

}
