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
import burp.dialog.SourceDialog;
import burp.dialog.UrlDialog;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

public class RemoteEndpointsButton extends EndpointsButton {

    public RemoteEndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        super(view, callbacks);
    }

    @Override
    protected String getButtonText() {
        return "Import Endpoints From ThreadFix";
    }

    @Override
    protected String getNoEndpointsMessage() {
        return "Did not retrieve any endpoints from ThreadFix. Check your Threadfix server settings.";
    }

    @Override
    protected String getCompletedMessage() { return "The endpoints were successfully imported from ThreadFix."; }

    @Override
    protected ConfigurationDialogs.DialogMode getDialogMode() {
        return ConfigurationDialogs.DialogMode.THREADFIX_APPLICATION;
    }

    @Override
    protected Endpoint.Info[] getEndpoints() {
        try {
            return RestUtils.getEndpoints();
        } catch (Exception e) {
            return new Endpoint.Info[0];
        }
    }
}
