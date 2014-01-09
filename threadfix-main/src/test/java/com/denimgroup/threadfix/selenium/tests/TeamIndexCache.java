package com.denimgroup.threadfix.selenium.tests;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TeamIndexCache {
    private static final String CASE_SENSITIVE = System.getProperty("CASE_SENSITIVE");
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
        if (CASE_SENSITIVE != null) {
            Collections.sort(list, String.CASE_INSENSITIVE_ORDER);
        } else {
            Collections.sort(list);
        }
    }

    public void addTeamWithName(String teamName) {
        list.add(teamName.trim());
        if (CASE_SENSITIVE != null) {
            Collections.sort(list, String.CASE_INSENSITIVE_ORDER);
        } else {
            Collections.sort(list);
        }
    }

    public void deleteTeamWithName(String teamName) {
        list.remove(teamName.trim());
    }

    public int getSize() {
        return list.size();
    }

    public Integer getIndex(String teamName) {
        assertTrue(list != null);
        int index = Collections.binarySearch(list, teamName.trim());
        if(index < 0) {
            System.out.println(teamName + " not found in cache. Returned Value: " + index);
            this.printList();
        }
        return (Collections.binarySearch(list, teamName.trim()) + 1);
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
