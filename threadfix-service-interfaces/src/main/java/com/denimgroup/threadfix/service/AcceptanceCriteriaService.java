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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.AcceptanceCriteria;

import java.util.List;

/**
 * Created by sgerick on 5/27/2015.
 */

/**
 *
 */
public interface AcceptanceCriteriaService {

    /**
     * @return all AcceptanceCriteria
     */
    List<AcceptanceCriteria> loadAll();

    /**
     * @param acceptanceCriteriaName
     * @return AcceptanceCriteria by name
     */
    AcceptanceCriteria loadAcceptanceCriteria(String acceptanceCriteriaName);

    /**
     * @param acceptanceCriteriaId
     * @return AcceptanceCriteria by id
     */
    AcceptanceCriteria loadAcceptanceCriteria(int acceptanceCriteriaId);

    /**
     * @param acceptanceCriteriaId
     */
    void deleteById(int acceptanceCriteriaId);

    /**
     * @param acceptanceCriteria
     */
    void delete(AcceptanceCriteria acceptanceCriteria);

    /**
     * @param acceptanceCriteria
     */
    void storeAcceptanceCriteria(AcceptanceCriteria acceptanceCriteria);

    /**
     * @param acceptanceCriteria
     */

    List<String> notificationEmailAddresses(AcceptanceCriteria acceptanceCriteria);
}
