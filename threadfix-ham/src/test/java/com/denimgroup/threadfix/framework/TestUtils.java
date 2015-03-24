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
package com.denimgroup.threadfix.framework;

import com.denimgroup.threadfix.framework.engine.partial.DefaultPartialMapping;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.setFrom;
import static org.junit.Assert.assertTrue;

public class TestUtils {

	@Nonnull
    public static List<PartialMapping> getMappings(@Nonnull String[][] strings) {
		List<PartialMapping> mappings = list();
		
		for (String[] stringArray : strings) {
			mappings.add(new DefaultPartialMapping(stringArray[0], stringArray[1]));
		}
		
		return mappings;
	}

    public static void compare(Collection<String> parsed, Collection<String> expected, String name) {
        Set<String> paramsCopy = setFrom(parsed),
                expectedCopy = setFrom(expected);

        paramsCopy.removeAll(expected);
        expectedCopy.removeAll(parsed);

        assertTrue(name + " has extra strings " + expectedCopy, expectedCopy.size() == 0);
        assertTrue(name + " were missing " + paramsCopy, paramsCopy.size() == 0);
    }
	
}
