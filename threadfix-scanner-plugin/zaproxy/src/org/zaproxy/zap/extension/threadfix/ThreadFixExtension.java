////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package org.zaproxy.zap.extension.threadfix;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

import javax.swing.JMenuItem;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

import com.denimgroup.threadfix.plugin.zap.action.EndpointsAction;
import com.denimgroup.threadfix.plugin.zap.action.ImportAction;

public class ThreadFixExtension extends ExtensionAdaptor {

    private JMenuItem importAction = null, endpointsAction = null;
    private ResourceBundle messages = null;

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    static {
       logger.info("Loading Class");
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    /**
     *
     */
    public ThreadFixExtension() {
        super();
        logger.info("calling constructor");
        initialize();
        logger.info("No-arg Constructor");
        this.setEnabled(true);
    }

    /**
     * @param name
     */
    public ThreadFixExtension(String name) {
        super(name);
        logger.info("1-arg Constructor");
    }

    /**
     * This method initializes this
     *
     */
    private void initialize() {
       logger.info("Initialize");
        this.setName("ThreadFix");
        // Load extension specific language files - these are held in the extension jar
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
       logger.info("Hook");
        super.hook(extensionHook);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list
            extensionHook.getHookMenu().addToolsMenuItem(getImportAction());
            extensionHook.getHookMenu().addToolsMenuItem(getEndpointsAction());
        }

    }

    private JMenuItem getImportAction() {
       logger.info("Getting menu");
        if (importAction == null) {
            importAction = new ImportAction(getView(), getModel());
        }
        return importAction;
    }

    private JMenuItem getEndpointsAction() {
       logger.info("Getting menu");
        if (endpointsAction == null) {
            endpointsAction = new EndpointsAction(getView(), getModel());
        }
        return endpointsAction;
    }

    public String getMessageString(String key) {
        return messages.getString(key);
    }
    @Override
    public String getAuthor() {
       logger.info("Getting Author");
        return "Denim Group";
    }

    @Override
    public String getDescription() {
       logger.info("Getting Description");
        return "ThreadFix integration";
    }

    @Override
    public URL getURL() {
       logger.info("Getting URL");
        try {
            return new URL("http://code.google.com/p/threadfix/wiki/ZapPlugin");
        } catch (MalformedURLException e) {
            return null;
        }
    }
}