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

package com.denimgroup.threadfix.importer.loader;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.utils.FolderMappings;
import org.junit.Test;
import org.mockito.InjectMocks;

import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ScanTypeCalculatorTests {

    @InjectMocks
    ScanTypeCalculationServiceImpl service = new ScanTypeCalculationServiceImpl();

    @Test
    public void testFalseNegatives() {
        for (ScannerType type : ScannerType.values()) {
            if (FolderMappings.containsKey(type)) {
                System.out.println(FolderMappings.getValue(type).size() + " scan file(s) found for " + type);
            } else {
                System.out.println("No items found for " + type + ". You should think about fixing that.");
            }
        }

        for (Map.Entry<ScannerType, Collection<String>> entry : FolderMappings.getEntries()) {
            for (String file : entry.getValue()) {
                String type = service.getScannerType(file, file);
                assertEquals("Failed for file " + file, entry.getKey().getDbName(), type);
            }
        }
    }

    @Test
    public void testFalsePositives() {
        for (ScannerType outerEntry : FolderMappings.getKeys()) {
            for (Map.Entry<ScannerType, Collection<String>> innerEntry : FolderMappings.getEntries()) {
                if (innerEntry.getKey() != outerEntry) {
                    for (String file : innerEntry.getValue()) {
                        String type = service.getScannerType(file, file);
                        assertFalse(outerEntry + " falsely identified file " + file, outerEntry.getDisplayName().equals(type));
                    }
                }
            }
        }
    }


}
