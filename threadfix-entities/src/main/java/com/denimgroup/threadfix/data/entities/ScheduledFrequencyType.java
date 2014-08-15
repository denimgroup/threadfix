package com.denimgroup.threadfix.data.entities;

/**
 * Created by zabdisubhan on 8/14/14.
 */

public enum ScheduledFrequencyType {
    DAILY("Daily"),
    WEEKLY("Weekly");

    private String description;

    public String getDescription() {
        return this.description;
    }

    private ScheduledFrequencyType(String description) {
        this.description = description;
    }

    public static ScheduledFrequencyType getFrequency(String keyword) {
        for (ScheduledFrequencyType t: values()) {
            if (keyword.equalsIgnoreCase(t.getDescription())) {
                return t;
            }
        }
        return null;
    }
}