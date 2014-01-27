package com.denimgroup.threadfix.plugins.intellij.rest;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.plugins.intellij.properties.IntelliJPropertiesManager;
import com.denimgroup.threadfix.remote.PluginClient;

/**
 * Created by mcollins on 1/24/14.
 */
public class ThreadFixApplicationService {

    public static ApplicationsMap getApplications() {

        Application.Info[] infoArray = new PluginClient(IntelliJPropertiesManager.INSTANCE).getThreadFixApplications();

        ApplicationsMap map = new ApplicationsMap();

        for (Application.Info info : infoArray) {
            map.addApp(info);
        }

        return map;
    }

}
