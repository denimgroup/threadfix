////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.engine.cleaner;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestUtils;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;

public class DefaultPathCleanerTests {
	
	@Test
	public void constructorTests2Arg() {
		
		String staticRoot = "/root", dynamicRoot = "/bodgeit";
		
		PathCleaner cleaner = new DefaultPathCleaner(staticRoot, dynamicRoot);
		
		assertTrue("Default cleaner didn't save the dynamic root correctly.",
				dynamicRoot.equals(cleaner.getDynamicRoot()));
		
		assertTrue("Default cleaner didn't save the static root correctly.",
				staticRoot.equals(cleaner.getStaticRoot()));
	}
	
	@NotNull
    String[][] base = {
		{ "/root/about.jsp", "/bodgeit/about.jsp" },
		{ "/root/admin.jsp", "/bodgeit/admin.jsp" },
		{ "/root/advanced.jsp", "/bodgeit/advanced.jsp"  },
		{ "/root/basket.jsp", "/bodgeit/basket.jsp"  },
		{ "/root/contact.jsp", "/bodgeit/contact.jsp"  },
		{ "/root/footer.jsp", "/bodgeit/footer.jsp"  },
		{ "/root/header.jsp", "/bodgeit/header.jsp"  },
		{ "/root/home.jsp", "/bodgeit/home.jsp"  },
		{ "/root/init.jsp", "/bodgeit/init.jsp"  },
		{ "/root/login.jsp", "/bodgeit/login.jsp" },
		{ "/root/logout.jsp", "/bodgeit/logout.jsp"  },
		{ "/root/password.jsp", "/bodgeit/password.jsp"  },
		{ "/root/product.jsp", "/bodgeit/product.jsp"  },
		{ "/root/register.jsp", "/bodgeit/register.jsp"  },
		{ "/root/score.jsp", "/bodgeit/score.jsp"  },
		{ "/root/search.jsp", "/bodgeit/search.jsp"  },
	};
	
	@Test
	public void constructorTests1Arg() {
		
		List<PartialMapping> mappings = TestUtils.getMappings(base);
		
		String dynamicRoot = "/bodgeit";
		String staticRoot = "/root";
		
		PathCleaner cleaner = new DefaultPathCleaner(mappings);
		
		assertTrue("Default cleaner didn't parse the dynamic root correctly. It got " + cleaner.getDynamicRoot(),
				dynamicRoot.equals(cleaner.getDynamicRoot()));
		
		assertTrue("Default cleaner didn't parse the static root correctly. It got " + cleaner.getStaticRoot(),
				staticRoot.equals(cleaner.getStaticRoot()));
	}
	
	@Test
	public void cleaningTests() {
		
		String staticRoot = "/root", dynamicRoot = "/bodgeit";
		
		PathCleaner cleaner = new DefaultPathCleaner(staticRoot, dynamicRoot);
		
		for (String[] test : base) {
			
			String
				dynamicResult = cleaner.cleanDynamicPath(test[1]),
				staticResult = cleaner.cleanStaticPath(test[0]);
			
			assertTrue("Failed on " + test[0] + ": Got " + staticResult + " and " + dynamicResult,
					dynamicResult.equals(staticResult));
		}
	}

    @Test(expected=NullPointerException.class)
    public void testGiveStaticNullArgument() {
        String staticRoot = "/root", dynamicRoot = "/bodgeit";
        PathCleaner cleaner = new DefaultPathCleaner(staticRoot, dynamicRoot);
        cleaner.cleanStaticPath(null);
    }

    @Test(expected=NullPointerException.class)
    public void testGiveDynamicNullArgument() {
        String staticRoot = "/root", dynamicRoot = "/bodgeit";
        PathCleaner cleaner = new DefaultPathCleaner(staticRoot, dynamicRoot);
        cleaner.cleanDynamicPath(null);
    }

	@Test
	public void nullCleaningTests() {
		PathCleaner cleaner = new DefaultPathCleaner(null, null);
		
		assertTrue(cleaner.toString() != null);
		
		for (String[] test : base) {
			
			String
				dynamicResult = cleaner.cleanDynamicPath(test[1]),
				staticResult = cleaner.cleanStaticPath(test[0]);
			
			assertTrue("Failed on " + test[1] + ": Got " + dynamicResult,
					dynamicResult.equals(dynamicResult));
			
			assertTrue("Failed on " + test[0] + ": Got " + staticResult,
					staticResult.equals(staticResult));
		}
		
		cleaner = new DefaultPathCleaner("/different", "/roots");
		
		assertTrue(cleaner.toString() != null);
		
		for (String[] test : base) {
			
			String
			dynamicResult = cleaner.cleanDynamicPath(test[1]),
			staticResult = cleaner.cleanStaticPath(test[0]);
			
			assertTrue("Failed on " + test[1] + ": Got " + dynamicResult,
					dynamicResult.equals(dynamicResult));
			
			assertTrue("Failed on " + test[0] + ": Got " + staticResult,
					staticResult.equals(staticResult));
		}
	}
	
	
}
