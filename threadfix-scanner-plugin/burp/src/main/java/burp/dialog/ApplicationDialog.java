package burp.dialog;

import burp.extention.RestUtils;
import burp.extention.ThreadFixPropertiesManager;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

public class ApplicationDialog {

    public static boolean show(Component view) {
        Map<String, String> applicationMap = getApplicationMap();
        String resultId = null;
        Object[] possibilities = applicationMap.keySet().toArray();

        if (possibilities.length != 0) {
	        ImageIcon icon = new ImageIcon("images/middle.gif");
	        Object idResult = JOptionPane.showInputDialog(
                    view,
	                "Pick an Application",
	                "Pick an Application",
	                JOptionPane.PLAIN_MESSAGE,
	                icon,
	                possibilities,
	                ThreadFixPropertiesManager.getAppId());
	        
	        if (idResult != null && !idResult.toString().trim().isEmpty() ) {
	        	// Got a valid result
	        	resultId = applicationMap.get(idResult);
	        	ThreadFixPropertiesManager.setAppId(resultId);
	        }
        } else {
            JOptionPane.showMessageDialog(view, "Failed while trying to get a list of applications from ThreadFix.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
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
