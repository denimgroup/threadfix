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

package com.denimgroup.threadfix.data.entities;

/**
 * Created by zabdisubhan on 8/14/14.
 */

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="ScheduledRemoteProviderImport")
public class ScheduledRemoteProviderImport extends ScheduledJob {

    private static final long serialVersionUID = 1223869621339558275L;

    public static ScheduledRemoteProviderImport getDefaultScheduledImport(){

        ScheduledRemoteProviderImport defaultScheduledImport = new ScheduledRemoteProviderImport();

        defaultScheduledImport.setFrequency(ScheduledFrequencyType.DAILY.getDescription());
        defaultScheduledImport.setHour(6);
        defaultScheduledImport.setMinute(0);
        defaultScheduledImport.setPeriod("AM");
        defaultScheduledImport.setDay(null);
        defaultScheduledImport.setScheduleType(SELECT);

        return defaultScheduledImport;
    }

}
