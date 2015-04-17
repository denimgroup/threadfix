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
package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import org.junit.Test;

/**
 * Created by mcollins on 4/16/15.
 */
public class SSVLDataFlowTests {

    @Test
    public void testParsesDataFlow() {
        Scan scan = ParserUtils.getScan("Manual/SSVL/example1.ssvl");

        boolean hasDataFlowElements = false;
        for (Finding finding : scan) {

            if (finding.getDataFlowElements() != null) {
                hasDataFlowElements = true;
            }
        }

        assert hasDataFlowElements : "No DataFlowElements found.";
    }


}
