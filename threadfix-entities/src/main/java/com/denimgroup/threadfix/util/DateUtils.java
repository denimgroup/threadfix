package com.denimgroup.threadfix.util;

import org.joda.time.DateTime;
import org.joda.time.Days;

import java.text.SimpleDateFormat;
import java.util.Calendar;

public class DateUtils {
    public static SimpleDateFormat PRINTABLE_FORMAT = new SimpleDateFormat("EEE, d MMMM yyyy");

    public static int getDaysBetween(Calendar now, Calendar target) {
        DateTime nowLocal = new DateTime(now.getTime());
        DateTime targetLocal = new DateTime(target.getTime());

        return Days.daysBetween(nowLocal.toLocalDate(), targetLocal.toLocalDate()).getDays();
    }
}
