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
package com.denimgroup.threadfix.plugins.intellij.action;

import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.dialog.ConfigDialog;
import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.denimgroup.threadfix.plugins.intellij.properties.Constants;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarkerService;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.diagnostic.Logger;

import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/3/13
 * Time: 1:50 PM
 * To change this template use File | Settings | File Templates.
 */
public class ImportAction extends AnAction {

    private static final Logger log = Logger.getInstance(ImportAction.class);

    public void actionPerformed(AnActionEvent e) {

        if (ConfigDialog.show(e)) {
            log.info(Constants.IMPORT_MARKERS_MESSAGE);

            List<VulnerabilityMarker> markers = VulnerabilityMarkerService.getAllMarkers();

            MarkerUtils.createMarkers(markers, e.getData(PlatformDataKeys.PROJECT));

            new ShowAction().actionPerformed(e);

        } else {
            log.info(Constants.CANCEL_PRESSED_MESSAGE);
        }
    }

}
