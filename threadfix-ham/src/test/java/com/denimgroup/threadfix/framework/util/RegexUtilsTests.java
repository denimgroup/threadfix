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
package com.denimgroup.threadfix.framework.util;

import com.denimgroup.threadfix.framework.impl.spring.SpringDataFlowParser;
import org.junit.Test;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.framework.util.RegexUtils.getRegexResult;
import static com.denimgroup.threadfix.framework.util.RegexUtils.getRegexResults;

/**
 * Created by mac on 7/10/14.
 */
public class RegexUtilsTests {

    @Test
    public void testMultipleMatches() {
        String targetString =
                "public String processFindForm(@RequestParam String lastName, @RequestParam String firstName) {";

        listCompare(list("lastName", "firstName"),
                getRegexResults(targetString, SpringDataFlowParser.REQUEST_PARAM_NO_PARAM));
    }

    @Test
    public void testSingleMatch() {
        String targetString =
                "public String processFindForm(@RequestParam String lastName) {";

        String result = getRegexResult(targetString, SpringDataFlowParser.REQUEST_PARAM_NO_PARAM);

        assert "lastName".equals(result) : result + " wasn't lastName";
    }

    @Test
    public void testModelParsing() {
        String targetString =
                "Collection<Owner> results = this.clinicService.findOwnerByLastName(pet.getOwner().getLastName());";

        List<String> results = getRegexResults(targetString, SpringDataFlowParser.getPatternForString("pet"));

        assert results.size() == 1 : "Got " + results.size() + " results instead of 1: " + results;

        assert results.contains(".getOwner()") : "Didn't have owner: " + results;

        results = getRegexResults(targetString, SpringDataFlowParser.getPatternForString("owner"));

        assert results.size() == 1 : "Got " + results.size() + " results instead of 1: " + results;

        assert results.contains(".getLastName())") : "Didn't have .getLastName()): " + results;
    }

    private <T> void listCompare(List<T> list1, List<T> list2) {
        assert list1.size() == list2.size() : list1 + " didn't match " + list2;

        for (int i = 0; i < list1.size(); i++) {
            assert list1.get(i).equals(list2.get(i)) :
                    list1.get(i) + " didn't match " + list2.get(i) +
                    " for lists " + list1 + " and " + list2;
        }
    }



}
