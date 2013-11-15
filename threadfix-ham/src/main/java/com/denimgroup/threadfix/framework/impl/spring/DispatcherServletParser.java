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
package com.denimgroup.threadfix.framework.impl.spring;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import org.jetbrains.annotations.NotNull;

public class DispatcherServletParser {
	
	private static final SanitizedLogger log = new SanitizedLogger("DispatcherServletParser");
	
	// this is much faster than an implementation using the tokenizer.
	public static boolean usesSpringMvcAnnotations(@NotNull File file) {
		boolean returnValue = false;
		
		if (file.exists()) {

			try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			
				String line = reader.readLine();
				while (line != null) {
					if (line.contains("mvc:annotation-driven")) {
						returnValue = true;
						break;
					}
					
					line = reader.readLine();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		if (!returnValue) {
			log.info("mvc:annotation-driven was not found, the annotations are not supported.");
		}
		
		return returnValue;
	}
}
