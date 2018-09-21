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

import com.denimgroup.threadfix.data.entities.GRCTool;
import com.denimgroup.threadfix.data.entities.GRCToolType;

import java.util.List;

/**
 * Created by zabdisubhan on 10/27/14.
 */
public interface GRCToolService {

    /**
     * @return List<GRCTool>
     */
    List<GRCTool> loadAllGrcTools();

    /**
     * @param grcToolId
     * @return GRCTool
     */
    GRCTool loadGrcTool(int grcToolId);

    /**
     * @param name
     * @return
     */
    GRCTool loadGrcTool(String name);

    /**
     * @param grcTool
     */
    void storeGrcTool(GRCTool grcTool);

    /**
     * @param grcToolId
     */
    void deleteById(int grcToolId);

    /**
     * @param grcTool
     */
    void delete(GRCTool grcTool);

    /**
     * @return GRCToolType
     */
    List<GRCToolType> loadAllGrcToolTypes();

    /**
     * @return GRCToolType
     */
    List<GRCToolType> loadAllUnusedGrcToolTypes();

    /**
     * @param grcToolTypeId
     * @return GRCToolType
     */
    GRCToolType loadGrcToolType(int grcToolTypeId);

    /**
     * @param name
     * @return GRCToolType
     */
    GRCToolType loadGrcToolType(String name);

    /**
     * @param grcToolType
     */
    void storeGrcToolType(GRCToolType grcToolType);

    /**
     *
     * @param grcTool
     * @return GRCTool
     */
    GRCTool decryptCredentials(GRCTool grcTool);

    /**
     *
     * @param appId
     * @return boolean
     */
    public boolean updateControlsFromGrcTool(Integer appId);
}
