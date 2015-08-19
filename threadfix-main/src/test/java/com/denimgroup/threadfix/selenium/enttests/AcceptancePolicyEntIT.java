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

package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.AcceptancePolicyPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class AcceptancePolicyEntIT extends BaseDataTest {

    private AcceptancePolicyPage initialize(String policyName) {
        String filterName = getName();

        return loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createAcceptancePolicy(policyName, filterName);
    }

    //================================================================================================
    // UI tests
    //================================================================================================

    @Test
    public void testCreateAcceptancePolicy() {
        String policyName = getName();
        String filterName = getName();
        AcceptancePolicyPage acceptancePolicyPage = loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createAcceptancePolicy(policyName, filterName);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(policyName));
        assertTrue("Policy name is not correct.", acceptancePolicyPage.isPolicyNameCorrect(policyName));
        assertTrue("Policy filter name is not correct.", acceptancePolicyPage.isPolicyFilterCorrect(filterName));
        assertTrue("Default policy status is not correct.", acceptancePolicyPage.isPolicyPassing(policyName));
    }

    @Test
    public void testDeleteAcceptancePolicy() {
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(name));

        acceptancePolicyPage.clickEditDeleteButton(name)
                .deletePolicy();

        assertFalse("Acceptance Policy is still present after deletion.", acceptancePolicyPage.isPolicyPresent(name));
    }

    @Test
    public void testEditAcceptancePolicy() {
        String policyName = getName();
        String editedPolicyName = getName();
        String newFilter = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(policyName)
                .createGenericFilter(newFilter);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(policyName));

        acceptancePolicyPage.clickEditDeleteButton(policyName)
                .setAcceptancePolicyName(editedPolicyName)
                .setFilterForPolicy(newFilter)
                .saveAcceptancePolicy();

        assertTrue("Acceptance Policy does not display edited name.", acceptancePolicyPage.isPolicyNameCorrect(editedPolicyName));
        assertTrue("Policy filter name is not the new filter.", acceptancePolicyPage.isPolicyFilterCorrect(newFilter));
    }
}
