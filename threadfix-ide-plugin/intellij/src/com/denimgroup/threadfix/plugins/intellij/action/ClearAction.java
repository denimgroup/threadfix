package com.denimgroup.threadfix.plugins.intellij.action;

import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/3/13
 * Time: 2:03 PM
 * To change this template use File | Settings | File Templates.
 */
public class ClearAction extends AnAction {
    public void actionPerformed(AnActionEvent e) {
        System.out.println("Clearing stuff");

        MarkerUtils.removeMarkers(e);
    }
}
