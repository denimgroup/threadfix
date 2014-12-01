////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer.interop;

import org.springframework.context.ApplicationContext;

import java.util.Calendar;
import java.util.List;

public interface ScannerMappingsUpdaterService {

    static class ScanPluginCheckBean {
        public final boolean canUpdate;
        public final Calendar lastImportDate;
        public final Calendar currentPluginDate;

        public boolean isCanUpdate() {
            return canUpdate;
        }

        public Calendar getLastImportDate() {
            return lastImportDate;
        }

        public Calendar getCurrentPluginDate() {
            return currentPluginDate;
        }

        public ScanPluginCheckBean(boolean canUpdate, Calendar lastImportDate, Calendar currentPluginDate) {
            this.canUpdate = canUpdate;
            this.lastImportDate = lastImportDate;
            this.currentPluginDate = currentPluginDate;
        }
    }

    /**
     *
     * @return
     */
    ScanPluginCheckBean checkPluginJar(ApplicationContext applicationContext);
    ScanPluginCheckBean checkPluginJar();

    /**
     *
     */
    List<String> getSupportedScanners();

    void updateMappings();

    void updateMappings(ApplicationContext applicationContext);

}
