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
package com.denimgroup.threadfix.service.waf;

import com.denimgroup.threadfix.annotations.WebApplicationFirewall;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.importer.loader.AnnotationKeyGenerator;
import com.denimgroup.threadfix.importer.loader.ImplementationLoader;
import org.springframework.stereotype.Service;

/**
 * @author bbeverly
 * 
 */
@Service
public class RealTimeProtectionGeneratorFactory {

	/**
	 * Returns an RealTimeProtectionGenerator implementation based on the
	 * application's waf name.
	 * 
	 * @param
	 * @return
	 */
	public RealTimeProtectionGenerator getTracker(Application app) {
		if (app == null || app.getWaf() == null || app.getWaf().getWafType() == null
				|| app.getWaf().getWafType().getName() == null) {
			return null;
		}

		String wafName = app.getWaf().getWafType().getName();

		return getTracker(wafName);
	}

	/**
	 * @param wafName
	 * @return
	 */
	public RealTimeProtectionGenerator getTracker(String wafName) {
		if (wafName == null || wafName.trim().equals("")) {
			return null;
		}

        if (loader == null) {
            init();
            assert loader != null : "Failed to initialize the WAF loader";
        }

        RealTimeProtectionGenerator implementation = loader.getImplementation(wafName);

        if (implementation == null) {
            throw new IllegalArgumentException("No implementation found for " + wafName);
        }

        return implementation;
	}

    ImplementationLoader<WebApplicationFirewall, RealTimeProtectionGenerator> loader = null;

    private void init() {

        loader = new ImplementationLoader<>(WebApplicationFirewall.class,
                RealTimeProtectionGenerator.class,
                "com.denimgroup.threadfix.service.waf",
                new AnnotationKeyGenerator<WebApplicationFirewall>() {
                    @Override
                    public String getKey(WebApplicationFirewall annotation) {
                        return annotation.name();
                    }
                });
    }

}
