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
package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;


@ScanImporter(
        scannerName = ScannerDatabaseNames.CONTRAST_DB_NAME,
        format = ScanFormat.JSON,
        jsonStructure = ScanImporter.JSONStructure.LIST_OF_OBJECTS,
        jsonProperties = {
                "total-traces-received",
                "reported-to-bug-tracker"
        }
)
public class ContrastChannelImporter extends AbstractChannelImporter{

    public ContrastChannelImporter() {
        super(ScannerType.CONTRAST);
    }

    @Override
    public Scan parseInput() {
        throw new UnsupportedOperationException("This scan should be uploaded via Remote Provider.");
    }

    @Override
    public ScanCheckResultBean checkFile() {
        throw new UnsupportedOperationException("This scan should be uploaded via Remote Provider.");
    }
}
