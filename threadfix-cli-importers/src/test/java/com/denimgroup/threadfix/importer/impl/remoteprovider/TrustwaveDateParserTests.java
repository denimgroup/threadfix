package com.denimgroup.threadfix.importer.impl.remoteprovider;

import org.junit.Test;

import java.util.Calendar;
import java.util.Date;

/**
 * Created by mcollins on 12/10/2014.
 */
public class TrustwaveDateParserTests {

    @Test
    public void testDateParsing() {
        //             yyyy-MM-dd'T'HH:mm:ss.SSSSSSS'Z'
        String sampleDate = "2014-04-28T19:14:42.0000000Z";

        TrustwaveHailstormRemoteProvider remoteProvider = new TrustwaveHailstormRemoteProvider();

        Date dateObject = remoteProvider.parseDate(sampleDate);

        assert dateObject != null : "Date was null for string " + sampleDate;

        Calendar calendar = Calendar.getInstance();

        calendar.setTime(dateObject);

        assert 2014 == calendar.get(Calendar.YEAR) : "Year was " + calendar.get(Calendar.YEAR) + " instead of 2014";
        assert 3 == calendar.get(Calendar.MONTH) : "Month was " + calendar.get(Calendar.MONTH) + " instead of 3";
        assert 28 == calendar.get(Calendar.DAY_OF_MONTH) : "Day was " + calendar.get(Calendar.DAY_OF_MONTH) + " instead of 28";
        assert 19 == calendar.get(Calendar.HOUR_OF_DAY) : "Hour was " + calendar.get(Calendar.HOUR) + " instead of 19";
    }
}
