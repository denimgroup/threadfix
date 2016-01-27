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
import burp.dialog.ConfigurationDialogs;
import burp.dialog.UrlDialog;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class EndpointsButton extends JButton {

    public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    public EndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        setText(getButtonText());

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean configured = ConfigurationDialogs.show(view, getDialogMode());
                boolean completed = false;
                java.util.List<String> nodes = new ArrayList<>();

                if (configured) {
                    Endpoint.Info[] endpoints = getEndpoints();

                    if (endpoints.length == 0) {
                        JOptionPane.showMessageDialog(view, getNoEndpointsMessage(), "Warning",
                                JOptionPane.WARNING_MESSAGE);
                    } else {
                        for (Endpoint.Info endpoint : endpoints) {
                            if (endpoint != null) {
                                String endpointPath = endpoint.getUrlPath();
                                if (endpointPath.startsWith("/")) {
                                    endpointPath = endpointPath.substring(1);
                                }
                                endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
                                nodes.add(endpointPath);

                                for (String parameter : endpoint.getParameters()) {
                                    nodes.add(endpointPath + "?" + parameter + "=true");
                                }
                            }
                        }

                        String url = UrlDialog.show(view);

                        if (url != null) { // cancel not pressed
                            try {
                                if (!url.substring(url.length() - 1).equals("/")) {
                                    url = url+"/";
                                }
                                for (String node: nodes) {
                                    callbacks.sendToSpider(new URL(url + node));
                                }
                                completed = true;
                            } catch (MalformedURLException e1) {
                                JOptionPane.showMessageDialog(view, "Invalid URL.",
                                        "Warning", JOptionPane.WARNING_MESSAGE);
                            }
                        }
                    }
                }

                if (completed) {
                    JOptionPane.showMessageDialog(view, getCompletedMessage());
                }
            }
        });
    }

    protected abstract String getButtonText();

    protected abstract String getNoEndpointsMessage();

    protected abstract String getCompletedMessage();

    protected abstract ConfigurationDialogs.DialogMode getDialogMode();

    protected abstract Endpoint.Info[] getEndpoints();
}
