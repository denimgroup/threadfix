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

package burp.custombutton;

import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;
import burp.dialog.ConfigurationDialogs;
import burp.extention.BurpPropertiesManager;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.remote.response.RestResponse;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class ExportButton extends JButton {

    public ExportButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        setText("Export Scan");
        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean configured = ConfigurationDialogs.show(view, ConfigurationDialogs.DialogMode.THREADFIX_APPLICATION);
                if (configured) {
                    IScanIssue[] issues = callbacks.getScanIssues(BurpPropertiesManager.getBurpPropertiesManager().getTargetUrl());
                    if ((issues == null) || (issues.length == 0)) {
                        JOptionPane.showMessageDialog(view, "There are currently no issues to upload to ThreadFix.",
                                "Warning", JOptionPane.WARNING_MESSAGE);
                    } else {
                        File file = generateXml(callbacks, issues);
                        if (file != null && file.exists()) {
                            RestResponse<Object> object = RestUtils.uploadScan(file);
                            if (object.responseCode == 0) {
                                JOptionPane.showMessageDialog(view, "The response code was 0, indicating that the ThreadFix server " +
                                        "was unreachable. Make sure that the server is running and not blocked by the BURP " +
                                        "local proxy.", "Warning", JOptionPane.WARNING_MESSAGE);
                            } else if (object.success) {
                                JOptionPane.showMessageDialog(view, "The scan was uploaded to ThreadFix successfully.");
                            } else {
                                JOptionPane.showMessageDialog(view, "The upload failed. The response code was " +
                                        object.responseCode +
                                        " and the error message was " +
                                        object.message);
                            }
                        } else {
                            // file didn't exist
                            JOptionPane.showMessageDialog(view, "Unable to create scan file.",
                                    "Warning", JOptionPane.WARNING_MESSAGE);
                        }
                    }
                }
            }
        });
    }

    private File generateXml(IBurpExtenderCallbacks callbacks, IScanIssue[] issues) {
        File file = new File("burp_threadfix.xml");
        callbacks.generateScanReport("XML", issues, file);
        return file;

    }
}
