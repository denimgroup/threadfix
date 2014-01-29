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
	                BurpPropertiesManager.getAppId());
	        
	        if (idResult != null && !idResult.toString().trim().isEmpty() ) {
	        	// Got a valid result
	        	resultId = applicationMap.get(idResult);
	        	BurpPropertiesManager.setAppId(resultId);
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
