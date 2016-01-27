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
package com.denimgroup.threadfix.plugin.zap.action;

import java.io.File;

import javax.swing.JMenuItem;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import com.denimgroup.threadfix.plugin.zap.dialog.ConfigurationDialogs;
import org.zaproxy.zap.extension.threadfix.AbstractZapPropertiesManager;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

public class ImportAction extends JMenuItem {

	private static final long serialVersionUID = 1L;
	
	private static final Logger logger = Logger.getLogger(ImportAction.class);

    private ViewDelegate view;
    private Model model;

    public ImportAction(final ViewDelegate view, final Model model) {
		logger.info("Initializing ThreadFix menu item: \"ThreadFix: Export Scan\"");
        setText("ThreadFix: Export Scan");

        this.view = view;
        this.model = model;

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                boolean configured = ConfigurationDialogs.show(view, ConfigurationDialogs.DialogMode.THREADFIX_APPLICATION);
                
                if (configured) {

                    logger.info("Got application id, about to generate XML and use REST call.");

                    ZapPropertiesManager manager = ZapPropertiesManager.INSTANCE;

                    Integer responseCode = uploadReport(manager);

                    if (responseCode == null) {
                        // file didn't exist
                        view.showWarningDialog("Unable to create scan file.");
                    } else if (responseCode == 0) {
                        view.showWarningDialog("The response code was 0, indicating that the ThreadFix server " +
                                "was unreachable. Make sure that the server is running and not blocked by the ZAP " +
                                "local proxy.");
                    } else if (responseCode == -2) {
                        view.showWarningDialog("The parameters were not saved correctly.");
                    } else if (responseCode != 200) {
                        view.showWarningDialog("Scan upload failed: the HTTP response code was " + responseCode +
                                " and not 200.");
                    } else {
                        view.showMessageDialog("The scan was uploaded to ThreadFix successfully.");
                    }
                }
            }
        });
    }

    public Integer uploadReport(AbstractZapPropertiesManager manager) {
        RestResponse<Object> response = uploadReportAndGetResponse(manager);

        if (response != null) {
            int responseCode = response.responseCode;
            return responseCode;
        } else {
            return null;
        }
    }

    public RestResponse<Object> uploadReportAndGetResponse(AbstractZapPropertiesManager manager) {
        File file = ReportGenerator.generateXml(view, model);

        if (file != null && file.exists()) {
            logger.info("About to try to upload.");
            RestResponse<Object> response = new PluginClient(manager)
                    .uploadScan(manager.getAppId(), file);

            return response;
        } else {
            return null;
        }
    }
}
