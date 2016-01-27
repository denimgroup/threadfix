////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.framework.impl.rails;

import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.framework.TestConstants.RAILSGOAT_SOURCE_LOCATION;
import static org.junit.Assert.assertTrue;

/**
 * Created by sgerick on 4/27/2015.
 */
public class RailsModelParserTest {

    private static final String[][] RAILSGOAT_MODELS = new String [][]{
    //  {"model", "param1", "param2", "param3"},
        {"analytics", "ip_address", "referrer", "user_agent"},
        {"benefits", "backup"},
        {"key_management", "iv", "user_id"},
        {"message", "creator_id", "message", "read", "receiver_id"},
        {"paid_time_off", "pto_earned", "pto_taken", "sick_days_earned", "sick_days_taken"},
        {"pay", "bank_account_num", "bank_routing_num", "percent_of_deposit"},
        {"performance", "comments", "date_submitted", "reviewer", "score"},
        {"retirement", "employee_contrib", "employer_contrib", "total"},
        {"schedule", "date_begin", "date_end", "event_desc", "event_name", "event_type"},
        {"user", "email", "admin", "first_name", "last_name", "user_id", "password",
                "password_confirmation", "skip_user_id_assign", "skip_hash_password"},
        {"work_info", "DoB", "SSN", "bonuses", "income", "years_worked"}
    };


    @Test
    public void testRailsGoatModelParser() {
        File f = new File(RAILSGOAT_SOURCE_LOCATION);
        assert(f.exists());
        assert(f.isDirectory());

        System.err.println("parsing "+f.getAbsolutePath() );
        Map modelMap = RailsModelParser.parse(f);
        System.err.println( System.lineSeparator() + "Parse done." + System.lineSeparator());
        compareModels(RAILSGOAT_MODELS, modelMap);

    }

    private void compareModels(String[][] testModels, Map modelMap) {
        for (String[] testModel : testModels) {
            String testModelName = testModel[0];
            assertTrue(testModelName + " not found in returned modelMap.",
                    modelMap.containsKey(testModelName));

            List<String> modelParams = (List<String>) modelMap.get(testModelName);
            List<String> testParams = new ArrayList<String>(testModel.length - 1);
            for (int i=1; i < testModel.length; i++) {
                testParams.add(testModel[i]);
            }
            assertTrue("Non-equal number of params in model " + testModelName
                            + ". Expected: " + testParams.size()
                            + ", Returned: " + modelParams.size(),
                    modelParams.size() == testParams.size());

            if (!modelParams.containsAll(testParams)) {
                for (String param : testParams) {
                    assertTrue(param + " not found as param in " + testModelName,
                            modelParams.contains(param));
                }
            }


        }

    }


}

