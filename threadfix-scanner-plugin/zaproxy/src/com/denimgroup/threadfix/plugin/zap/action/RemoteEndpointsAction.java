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

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.plugin.zap.dialog.ConfigurationDialogs;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.threadfix.AbstractZapPropertiesManager;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

public class RemoteEndpointsAction extends EndpointsAction {

    private static final long serialVersionUID = 1L;

	private static final Logger LOGGER = Logger.getLogger(RemoteEndpointsAction.class);

    public RemoteEndpointsAction(final ViewDelegate view, final Model model) {
        super(view, model);
    }

    @Override
    protected String getMenuItemText() {
        return "ThreadFix: Import Endpoints From ThreadFix";
    }

    @Override
    protected String getNoEndpointsMessage() {
        return "Failed to retrieve endpoints from ThreadFix. Check your key and url.";
    }

    @Override
    protected String getCompletedMessage() {
        return "The endpoints were successfully imported from ThreadFix.";
    }

    @Override
    protected ConfigurationDialogs.DialogMode getDialogMode() {
        return ConfigurationDialogs.DialogMode.THREADFIX_APPLICATION;
    }

    @Override
    protected Logger getLogger() {
        return LOGGER;
    }

    @Override
    public Endpoint.Info[] getEndpoints() {
        RestResponse<Endpoint.Info[]> response = getEndpointsResponse(ZapPropertiesManager.INSTANCE);
        if (response.success) {
            return response.object;
        } else {
            return new Endpoint.Info[]{};
        }
    }

    public RestResponse<Endpoint.Info[]> getEndpointsResponse(AbstractZapPropertiesManager propertiesManager) {
        getLogger().info("Got application id, about to generate XML and use REST call.");

        RestResponse<Endpoint.Info[]> response = new PluginClient(propertiesManager)
                .getEndpointsResponse(propertiesManager.getAppId());

        return response;
    }
}
