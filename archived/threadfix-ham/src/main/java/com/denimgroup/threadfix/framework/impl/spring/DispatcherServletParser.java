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
package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.io.*;

public class DispatcherServletParser {
	
	private static final SanitizedLogger log = new SanitizedLogger("DispatcherServletParser");
	
	// this is much faster than an implementation using the tokenizer.
	public static boolean usesSpringMvcAnnotations(@Nonnull File file) {
		boolean returnValue = false;
		
		if (file.exists()) {
			BufferedReader reader = null;

			try {
				reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));

				String line = reader.readLine();
				while (line != null) {
					if (line.contains("annotation-driven") || line.contains("context:component-scan")) {
						returnValue = true;
						break;
					}
					
					line = reader.readLine();
				}
			} catch (IOException e) {
				log.error("Encountered IOException while trying to read stream.", e);
			} finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (IOException e) {
						log.error("Encountered IOException while trying to close stream.", e);
					}
				}
			}
		}
		
		if (!returnValue) {
			log.info("annotation-driven was not found, the annotations are not supported.");
		}
		
		return returnValue;
	}
}
