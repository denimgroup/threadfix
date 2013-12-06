package com.denimgroup.threadfix.plugins.intellij.action;

import com.denimgroup.threadfix.plugins.intellij.dialog.ConfigDialog;
import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarkerService;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;

import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/3/13
 * Time: 1:50 PM
 * To change this template use File | Settings | File Templates.
 */
public class ImportAction extends AnAction {
    public void actionPerformed(AnActionEvent e) {

        if (ConfigDialog.show(e)) {
            System.out.println("Importing markers.");

            List<VulnerabilityMarker> markers = VulnerabilityMarkerService.getMarkers();

            MarkerUtils.createMarkers(markers, e);

        } else {
            System.out.println("Cancel pressed.");
        }
    }

}
