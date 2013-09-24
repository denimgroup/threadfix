package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: mcollins
 * Date: 9/24/13
 * Time: 10:27 AM
 * To change this template use File | Settings | File Templates.
 */
public class ApplicationDialog {

    private static final Logger logger = Logger.getLogger(ApplicationDialog.class);

    public static void show(ViewDelegate view) {

        Map<String, String> applicationMap = getApplicationMap();

        Object[] possibilities = applicationMap.keySet().toArray();
        ImageIcon icon = new ImageIcon("images/middle.gif");
        Object idResult = JOptionPane.showInputDialog(
                view.getMainFrame(),
                "Pick an Application",
                "Pick an Application",
                JOptionPane.PLAIN_MESSAGE,
                icon,
                possibilities,
                "1");

        logger.info("Got application ID: " + applicationMap.get(idResult));

        ThreadFixPropertiesManager.setAppId(applicationMap.get(idResult));
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
