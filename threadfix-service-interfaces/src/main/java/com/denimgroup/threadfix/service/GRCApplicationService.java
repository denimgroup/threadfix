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

import com.denimgroup.threadfix.data.entities.GRCApplication;

import java.util.List;

/**
 * @author zabdisubhan
 *
 */
public interface GRCApplicationService {
    /**
     * @return List<GRCApplication>
     */
    List<GRCApplication> loadAll();

    /**
     * @param grcApplicationId
     * @return GRCApplication
     */
    GRCApplication load(int grcApplicationId);

    /**
     * @param name
     * @return GRCApplication
     */
    GRCApplication load(String name);

    /**
     * @param nativeId
     * @return GRCApplication
     */
    GRCApplication loadByNativeId(String nativeId);

    /**
     * @param policyNumber
     * @return GRCApplication
     */
    GRCApplication loadByPolicyNumber(String policyNumber);

    /**
     * @param grcApplication
     */
    void store(GRCApplication grcApplication);

    /**
     * @param grcApplication
     */
    void delete(GRCApplication grcApplication);

    /**
     * @param grcApplicationId
     */
    void deleteById(int grcApplicationId);

    /**
     * @param grcApplicationId
     * @param applicationId
     * @return String
     */
    public String processApp(int grcToolId, int grcApplicationId, int applicationId);

    /**
     * @param grcApplication
     * @return String
     */
    public String deleteMapping(GRCApplication grcApplication);
}
