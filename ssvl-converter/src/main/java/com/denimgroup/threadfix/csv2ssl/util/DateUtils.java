package com.denimgroup.threadfix.csv2ssl.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static com.denimgroup.threadfix.csv2ssl.checker.Configuration.CONFIG;

/**
 * Created by mcollins on 12/10/2014.
 */
public class DateUtils {

    public static SimpleDateFormat
            OUR_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss aaa XXX"),
            THEIR_DATE_FORMAT = new SimpleDateFormat(CONFIG.dateString)
    ;

    public static String getCurrentTimestamp() {
        return OUR_DATE_FORMAT.format(new Date());
    }

    public static String toOurFormat(String dateString) {
        try {
            return OUR_DATE_FORMAT.format(THEIR_DATE_FORMAT.parse(dateString));
        } catch (ParseException e) {
            System.out.println("Failed to parse date " + dateString + " using pattern " + Strings.DATE_FORMAT);

            if (InteractionUtils.getYNAnswer("Would you like to configure the date pattern? (y/n)")) {
                System.out.println("Grammar reference: http://docs.oracle.com/javase/7/docs/api/java/text/SimpleDateFormat.html");
                CONFIG.dateString = InteractionUtils.getLine();
                THEIR_DATE_FORMAT = new SimpleDateFormat(CONFIG.dateString);
                return toOurFormat(dateString);
            } else {
                return null;
            }
        }
    }

}
