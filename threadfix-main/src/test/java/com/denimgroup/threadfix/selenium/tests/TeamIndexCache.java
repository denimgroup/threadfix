package com.denimgroup.threadfix.selenium.tests;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class TeamIndexCache {

    private static TeamIndexCache INSTANCE = null;

    private TeamIndexCache(){}

    public static TeamIndexCache getCache() {
        if (INSTANCE == null) {
            INSTANCE = new TeamIndexCache();
        }

        return INSTANCE;
    }

    public void clear() {
        list = null;
        initialized = false;
    }

    List<String> list = null;
    boolean initialized = false;

    public boolean isInitialized() {
        return initialized;
    }

    public void initialize(List<String> initialList) {
        list = initialList;
        initialized = true;
    }

    public void addTeamWithName(String teamName) {
        list.add(teamName);
        Collections.sort(list);
    }

    public void deleteTeamWithName(String teamName) {
        list.remove(teamName);
    }

    public int getSize() {
        return list.size();
    }

    public boolean isPresent(String teamName){
        return list.contains(teamName);
    }

    public Integer getIndex(String teamName) {
        assertTrue(list != null);
        return (Collections.binarySearch(list, teamName) + 1);
    }

    public void printList(){
        int i = 0;
        while (i < this.getSize()){
            System.out.print("[" + i + "]");
            System.out.println(list.get(i));
            i++;
        }
    }
}
