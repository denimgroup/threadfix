package com.denimgroup.threadfix.plugins.intellij.rest;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/5/13
 * Time: 1:42 PM
 * To change this template use File | Settings | File Templates.
 */
public class ApplicationsMap {

    private final Map<String,Map<String, String>> map =
            new HashMap<String,Map<String, String>>();

    private void addTeam(String team) {
        if (!map.containsKey(team)) {
            map.put(team, new HashMap<String, String>());
        }
    }

    void addApp(String team, String app, String id) {
        addTeam(team);
        map.get(team).put(app, id);
    }

    public Set<String> getTeams() {
        return map.keySet();
    }

    public Set<String> getApps(String team) {
        return map.get(team).keySet();
    }

    public String getId(String team, String app) {
        return map.get(team).get(app);
    }
}