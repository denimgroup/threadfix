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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Policy;
import com.denimgroup.threadfix.data.entities.PolicyStatus;
import com.denimgroup.threadfix.data.entities.Application;

import java.util.List;

/**
 * @author zabdisubhan
 */
public interface PolicyStatusService extends GenericObjectService<PolicyStatus> {

    void delete(PolicyStatus policyStatus);

    void addStatus(Policy policy, Application application);

    void removeStatus(Policy policy, Integer applicationId);

    void runStatusCheck(Policy policy);

    void runStatusCheck(int applicationId);

    void runStatusCheck(Application application);

    boolean passFilters(Application application);

    boolean passFilters(Policy policy);

    List<String> getNotificationEmailAddresses(PolicyStatus policyStatus);

}
