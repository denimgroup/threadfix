package com.denimgroup.threadfix.csv2ssl.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by mcollins on 12/10/2014.
 */
public class DateUtils {

    public static final SimpleDateFormat
            OUR_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss aaa XXX"),
            THEIR_DATE_FORMAT = new SimpleDateFormat(Strings.DATE_FORMAT)
    ;

    public static String getCurrentTimestamp() {
        return OUR_DATE_FORMAT.format(new Date());
    }

    public static String toOurFormat(String dateString) {
        return convertTo(dateString, OUR_DATE_FORMAT, THEIR_DATE_FORMAT);
    }

    public static String convertTo(String dateString, SimpleDateFormat ours, SimpleDateFormat theirs) {
        try {
            return OUR_DATE_FORMAT.format(THEIR_DATE_FORMAT.parse(dateString));
        } catch (ParseException e) {
            System.out.println("Failed to parse date " + dateString + " using pattern " + Strings.DATE_FORMAT);
            return null;
        }
    }

}
