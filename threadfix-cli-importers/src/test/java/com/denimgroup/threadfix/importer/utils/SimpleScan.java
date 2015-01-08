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

package com.denimgroup.threadfix.importer.utils;

import java.util.Iterator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 2/6/14.
 */
public class SimpleScan implements Iterable<SimpleFinding> {

    private final List<SimpleFinding> simpleFindings;

    public SimpleScan(List<SimpleFinding> simpleFindings) {
        this.simpleFindings = simpleFindings;
    }

    public static SimpleScan fromStringArray(String[][] strings) {
        List<SimpleFinding> findings = list();
        for (String[] line : strings) {
            findings.add(new SimpleFinding(line));
        }
        return new SimpleScan(findings);
    }

    @Override
    public Iterator<SimpleFinding> iterator() {
        return simpleFindings.iterator();
    }
}
