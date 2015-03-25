package com.denimgroup.threadfix.csv2ssl;

import com.denimgroup.threadfix.csv2ssl.util.DateUtils;
import org.junit.Test;

import java.text.SimpleDateFormat;

/**
 * Created by mcollins on 12/10/2014.
 */
public class DateUtilsTests {

    SimpleDateFormat OURS = DateUtils.OUR_DATE_FORMAT, THEIRS = new SimpleDateFormat("dd/MM/yyyy");

    String[][] tests = {
            { "05/10/2014", "2014-10-05 00:00:00" },
            { "3/11/2014",  "2014-11-03 00:00:00" },
    };

    @Test
    public void testConversions() {
        for (String[] test : tests) {
            test(test[0], test[1]);
        }
    }

    private void test(String dateString, String prefix) {

        DateUtils.THEIR_DATE_FORMAT = THEIRS;
        DateUtils.OUR_DATE_FORMAT = OURS;

        String converted = DateUtils.toOurFormat(dateString);

        assert converted.startsWith(prefix) :
                dateString + " converted to " + converted + " which didn't start with " + prefix;
    }


}
