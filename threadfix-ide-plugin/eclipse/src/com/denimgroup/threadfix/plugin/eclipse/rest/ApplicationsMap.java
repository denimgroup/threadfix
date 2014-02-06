package com.denimgroup.threadfix.plugin.eclipse.rest;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ApplicationsMap {
	private final Map<String,Map<String, String>> map =
            new HashMap<String,Map<String, String>>();

    private void addTeam(String team) {
        if (!map.containsKey(team)) {
            map.put(team, new HashMap<String, String>());
        }
    }

    public void addApp(String team, String app, String id) {
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
