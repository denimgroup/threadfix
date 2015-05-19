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

            String editedDateString = dateString;

            // if we have 3 but not 4 Ms
            if (CONFIG.dateString.contains("MMM") && !CONFIG.dateString.contains("MMMM")) {
                // SimpleDateFormat doesn't parse Sept but humans do
                editedDateString = editedDateString.replaceAll("Sept", "Sep");
            }

            return OUR_DATE_FORMAT.format(THEIR_DATE_FORMAT.parse(editedDateString));
        } catch (ParseException e) {
            System.out.println("Failed to parse date " + dateString + " using pattern " + CONFIG.dateString);

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
