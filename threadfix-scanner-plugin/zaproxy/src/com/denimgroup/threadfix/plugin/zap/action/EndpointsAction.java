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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JMenuItem;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.remote.PluginClient;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import com.denimgroup.threadfix.plugin.zap.dialog.ConfigurationDialogs;
import com.denimgroup.threadfix.plugin.zap.dialog.UrlDialog;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

public abstract class EndpointsAction extends JMenuItem {

	public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    private AttackThread attackThread = null;

    List<String> nodes = new ArrayList<>();

    public EndpointsAction(final ViewDelegate view, final Model model) {
        getLogger().info("Initializing ThreadFix menu item: \"" + getMenuItemText() + "\"");
        setText(getMenuItemText());

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                getLogger().info("About to show dialog.");
                
                boolean configured = ConfigurationDialogs.show(view, getDialogMode());
                boolean completed = false;
                
                if (configured) {
	                Endpoint.Info[] endpoints = getEndpoints();

                    if ((endpoints == null) || (endpoints.length == 0)) {
	                	view.showWarningDialog(getNoEndpointsMessage());
	                } else {

                        getLogger().info("Got " + endpoints.length + " endpoints.");

                        buildNodesFromEndpoints(endpoints);

		                String url = UrlDialog.show(view);

                        if (url != null) { // cancel not pressed
                            completed = attackUrl(url);
                            if (!completed) {
                                view.showWarningDialog("Invalid URL.");
                            }
                        }
	                }
                }

                if (completed) {
                	view.showMessageDialog(getCompletedMessage());
                }
            }
        });
    }

    public void buildNodesFromEndpoints(Endpoint.Info[] endpoints) {
        for (Endpoint.Info endpoint : endpoints) {
            getLogger().debug("  " + endpoint.getCsvLine());
            if (endpoint != null) {

                String urlPath = endpoint.getUrlPath();

                if (urlPath.startsWith("/")) {
                    urlPath = urlPath.substring(1);
                }

                urlPath = urlPath.replaceAll(GENERIC_INT_SEGMENT, "1");

                nodes.add(urlPath);

                Set<String> params = endpoint.getParameters();

                if (!params.isEmpty()) {
                    for(String parameter : params){
                        nodes.add(urlPath + "?" + parameter + "=true");
                    }
                }
            }
        }
    }

    public boolean attackUrl(String url) {
        try {
            if(!url.substring(url.length()-1).equals("/")){
                url = url+"/";
            }
            attack(new URL(url));
            return true;
        } catch (MalformedURLException e1) {
            getLogger().warn("Bad URL format.");
            return false;
        }
    }

    private void attack (URL url) {
        getLogger().info("Starting url " + url);

        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(this);
        attackThread.setNodes(nodes);
        attackThread.setURL(url);
        attackThread.start();

    }

    protected abstract String getMenuItemText();

    protected abstract String getNoEndpointsMessage();

    protected abstract String getCompletedMessage();

    protected abstract ConfigurationDialogs.DialogMode getDialogMode();

    protected abstract Logger getLogger();

    public abstract Endpoint.Info[] getEndpoints();

    public void notifyProgress(AttackThread.Progress progress) {
        getLogger().info("Status is " + progress);
    }

}
