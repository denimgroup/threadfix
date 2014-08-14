package com.denimgroup.threadfix.data.entities;

/**
 * Created by dzabdi88 on 8/14/14.
 */

public enum DayInWeek {
    MON("Monday"),
    TUE("Tuesday"),
    WED("Wednesday"),
    THU("Thursday"),
    FRI("Friday"),
    SAT("Saturday"),
    SUN("Sunday");

    private String day;

    public String getDay() {
        return this.day;
    }

    private DayInWeek(String day) {
        this.day = day;
    }

    public static DayInWeek getDay(String keyword) {
        for (DayInWeek t: values()) {
            if (keyword != null && keyword.equalsIgnoreCase(t.getDay())) {
                return t;
            }
        }
        return null;
    }
}