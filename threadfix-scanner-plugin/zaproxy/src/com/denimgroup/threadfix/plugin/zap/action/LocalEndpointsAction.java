////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.plugin.zap.dialog.ConfigurationDialogs;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

import java.util.List;

public class LocalEndpointsAction extends EndpointsAction {

    // TODO: generate a new serialVersionUID
	private static final long serialVersionUID = 0;

	private static final Logger LOGGER = Logger.getLogger(LocalEndpointsAction.class);

    public LocalEndpointsAction(final ViewDelegate view, final Model model) {
        super(view, model);
    }

    @Override
    protected String getMenuItemText() {
        return "ThreadFix: Import Endpoints From Source";
    }

    @Override
    protected String getNoEndpointsMessage() {
        // TODO: should this message be more dynamic based on what inputs were given?
        return "Failed to retrieve endpoints from the source. Check your inputs.";
    }

    @Override
    protected String getCompletedMessage() {
        return "The endpoints were successfully generated from source.";
    }

    @Override
    protected ConfigurationDialogs.DialogMode getDialogMode() {
        return ConfigurationDialogs.DialogMode.SOURCE;
    }

    @Override
    protected Logger getLogger() {
        return LOGGER;
    }

    @Override
    protected Endpoint.Info[] getEndpoints() {
        getLogger().info("Got source information, about to generate endpoints.");

        // TODO: endpointDatabase should be generated based on source info in properties, could be a directory name or a repo URL
        EndpointDatabase endpointDatabase = EndpointDatabaseFactory.getDatabase(ZapPropertiesManager.INSTANCE.getRepositoryFolder());

        Endpoint.Info[] endpoints = null;
        if (endpointDatabase != null) {
            List<Endpoint> endpointList = endpointDatabase.generateEndpoints();
            endpoints = new Endpoint.Info[endpointList.size()];
            int i = 0;
            for (Endpoint endpoint : endpointList) {
                endpoints[i++] = Endpoint.Info.fromEndpoint(endpoint);
            }
        }

        return endpoints;
    }
}
