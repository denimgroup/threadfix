////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Riverbed Technology
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.waflog;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.io.StringReader;
import java.io.IOException;

import org.apache.commons.csv.CSVRecord;
import org.apache.commons.csv.CSVFormat;

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.logging.SanitizedLogger;

/**
 * @author: Mirko Dziadzka, Riverbed Technology
 *
 */
public class RiverbedWebAppFirewallLogParser extends WafLogParser {

    protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
    private static final String THREADFIX_HANDLER_NAME = "ThreadfixHandler";
    private static final String THREADFIX_HANDLER_COMPONENT = "protection_rules";
    private static final String LOG_TIMESTAMP_FORMAT = "yyyyMMdd-HHmmss"; // 20140131-172342
    private static final String WAF_LOG_MODE_PROTECTION = "P";
    private static final String WAF_LOG_MODE_DETECTION = "D";

    /**
     * @param wafRuleDao
     * @param securityEventDao
     */
    public RiverbedWebAppFirewallLogParser(WafRuleDao wafRuleDao, SecurityEventDao securityEventDao) {
        this.wafRuleDao = wafRuleDao;
        this.securityEventDao = securityEventDao;
    }

    /**
     * @param entryBuffer
     * @return
     */
    @Override
    public SecurityEvent getSecurityEvent(String entry) {
        if (entry == null || entry.isEmpty() || entry.startsWith("#")) {
            return null;
        }

        // a logline is a csv encoded line with the following columns
        //  * [0] a timestamp: YYYYMMDD-HHMMSS in local time
        //  * [1] an internal session id or "default"
        //  * [2] internal cluster node id
        //  * [3] host header
        //  * [4] client ip
        //  * [5] HTTP method
        //  * [6] URL
        //  * [7] HTTP protocol version
        //  * [8] internal ruleset / rule id
        //  * [9] action
        //  * [10] protection or detection mode
        //  * [11] request or response
        //  * [12] handlerName - we only care for the THREADFIX_HANDLER_NAME here
        //  * [13] component which reject the request
        //  * [14] value which rejects the request
        //  * [16] error id (use this together with the timetamp to be unique)
        //  * [17] free text field
        //  * ... aditional stuff

        try {
            // we are using an iterator here because this
            // is the interface of this CSV parser 
            // however, we always feed only one line into
            // this parser so it is ok to return from this
            // loop and never continue
            Iterable<CSVRecord> parser = CSVFormat.DEFAULT.parse(new StringReader(entry));
            for (CSVRecord record : parser) {

                // We access elements 0 .. 17 later, so this has to have at least 18 elements
                if (record.size() < 18) {
                    log.error("can't parse logline: " + entry);
                    return null;
                }
                String csvTimestamp = record.get(0); 		// 20140131-172342
                String csvClientIP = record.get(4);		// 10.17.23.41
                String csvRulesetMode = record.get(10);		// P or D
                String csvHandlerName = record.get(12);		// ThreadfixHandler
                String csvComponentName = record.get(13);	// protection_ruleset
                String csvComponentValue = record.get(14);	// threadfix:100042 or 100042
                String csvErrorId = record.get(16);		// 1234567
                String csvFreeText = record.get(17);		// free text which describe the action

                if (csvTimestamp == null || csvClientIP == null || csvHandlerName == null || csvRulesetMode == null
                        || csvComponentName == null || csvComponentValue == null || csvErrorId == null || csvFreeText == null) {

                    log.error("can't parse logline: " + entry);
                    return null;
                }

                // we only care for THREADFIX_HANDLER_NAME here ... ignore all other stuff
                if (!csvHandlerName.equals(THREADFIX_HANDLER_NAME)) {
                    log.debug("ignore unknown handler: " + csvHandlerName);
                    return null;
                }

                // while the error id act more or less as
                // a unique id for rejected requests, this id
                // is too short to be really unique over a
                // long time. So we combine it here with the
                // timestamp to get a better native id
                String nativeId = csvTimestamp + "-" + csvErrorId;

                log.debug("native id: " + nativeId);

                if (securityEventDao.retrieveByNativeIdAndWafId(nativeId, wafId) != null) {
                    return null;
                }

                String wafRuleId = null;
                if (csvComponentName.equals(THREADFIX_HANDLER_COMPONENT)) {
                    // allow threadfix:123456 and 123456
                    if (csvComponentValue.contains(":")) {
                        wafRuleId = csvComponentValue.split(":", 2)[1];
                    } else {
                        wafRuleId = csvComponentValue;
                    }
                } else {
                    log.debug("ignore unknown component: " + csvComponentName);
                    return null;
                }

                log.debug("wafRuleId " + wafRuleId);

                WafRule rule = wafRuleDao.retrieveByWafAndNativeId(wafId, wafRuleId);
                if (rule == null) {
                    log.debug("wafRule not found");
                    return null;
                }

                Calendar calendar = parseDate(csvTimestamp);

                if (calendar == null) {
                    log.error("can't parse logline (timestamp): " + entry);
                    return null;
                }

                SecurityEvent event = new SecurityEvent();

                event.setWafRule(rule);
                event.setImportTime(calendar);
                event.setLogText(csvFreeText);

                event.setAttackType("deny");
                //if (csvRulesetMode == WAF_LOG_MODE_PROTECTION)
                //{
                //    event.setAttackType("deny");
                //} else {
                //    event.setAttackType("log"); 
                //}
                event.setNativeId(nativeId);
                event.setAttackerIP(csvClientIP);


                return event;
            }
        } catch (IOException e) {
            return null;
        }
        return null;

    }

    public static Calendar parseDate(String time) {
        SimpleDateFormat formatter = new SimpleDateFormat(LOG_TIMESTAMP_FORMAT);
        Date date = null;

        if (time == null) {
            return null;
        }

        try {
            date = formatter.parse(time);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        if (date == null) {
            return null;
        }

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);

        return calendar;
    }
}
