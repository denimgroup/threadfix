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

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;

import java.util.List;

public interface ScanResultFilterService {
    List<ScanResultFilter> loadAll();

    void storeAndApplyFilter(ScanResultFilter scanResultFilter);

    ScanResultFilter loadById(int scanResultFilterId);

    void delete(ScanResultFilter scanResultFilter);

    List<GenericSeverity> loadFilteredSeveritiesForChannelType(ChannelType channelType);

    ScanResultFilter loadByChannelTypeAndSeverity(ChannelType channelType, GenericSeverity genericSeverity);

    void storeAndApplyFilter(ScanResultFilter scanResultFilter, GenericSeverity previousGenericSeverity, ChannelType previousChannelType);
}
