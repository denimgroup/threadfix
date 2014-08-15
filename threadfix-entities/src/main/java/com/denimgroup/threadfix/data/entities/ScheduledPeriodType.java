package com.denimgroup.threadfix.data.entities;

/**
 * Created by zabdisubhan on 8/14/14.
 */

public enum ScheduledPeriodType {
    AM("AM"),
    PM("PM");

    private String period;

    public String getPeriod() {
        return this.period;
    }

    private ScheduledPeriodType(String period) {
        this.period = period;
    }

    public static ScheduledPeriodType getPeriod(String keyword) {
        for (ScheduledPeriodType t: values()) {
            if (keyword.equalsIgnoreCase(t.getPeriod())) {
                return t;
            }
        }
        return null;
    }
}
