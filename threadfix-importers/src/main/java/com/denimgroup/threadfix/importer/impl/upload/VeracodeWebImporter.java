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
package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;

import javax.annotation.Nonnull;

@ScanImporter(
        scannerName = ScannerDatabaseNames.VERACODE_DB_NAME,
        startingXMLTags = {"detailedreport", "static-analysis", "modules", "module"})
public class VeracodeWebImporter extends AbstractChannelImporter{
    public VeracodeWebImporter() { super(ScannerType.VERACODE); }

    @Override
    public Scan parseInput() {
        throw new UnsupportedOperationException("This should be uploaded via Remote Provider.");
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
        throw new UnsupportedOperationException("This should be uploaded via Remote Provider.");
    }

}
