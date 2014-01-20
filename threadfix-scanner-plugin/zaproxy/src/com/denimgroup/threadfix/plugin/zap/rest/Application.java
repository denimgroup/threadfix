package com.denimgroup.threadfix.plugin.zap.rest;

/**
 * Created by mac on 1/20/14.
 */
public class Application {

    private String name, id, teamName;

    public Application(String name, String id, String teamName) {
        this.name = name;
        this.id = id;
        this.teamName = teamName;
    }

    public String getCombinedName() {
        return teamName + "/" + name;
    }

    public String getId() {
        return id;
    }
}
