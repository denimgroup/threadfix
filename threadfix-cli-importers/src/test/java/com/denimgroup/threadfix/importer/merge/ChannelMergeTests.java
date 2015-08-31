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
package com.denimgroup.threadfix.importer.merge;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.parser.DependencyCheckTests;
import com.denimgroup.threadfix.service.merge.Merger;
import org.junit.Test;

import java.util.List;

/**
 * Created by mac on 7/28/14.
 */
public class ChannelMergeTests {

    /**
     * This name is terrible, let's think about renaming channel merge
     * Should have 124 findings with no merges
     */
    @Test
    public void testChannelMergeMergingOff() {
        Application application = new Application();
        application.setSkipApplicationMerge(true);
        List<Scan> scans = Merger.getScanListFromPaths(application, ScannerType.DEPENDENCY_CHECK, DependencyCheckTests.FILE_PATH);

        assert scans.size() == 1 : "Had " + scans.size() + " scans instead of 1 scan.";

        int size = scans.get(0).getFindings().size();

        assert size == 124 : "Got " + size + " instead of 124 findings.";
    }

}
