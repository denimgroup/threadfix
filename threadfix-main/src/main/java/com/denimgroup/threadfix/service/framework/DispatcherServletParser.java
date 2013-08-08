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
package com.denimgroup.threadfix.service.framework;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class DispatcherServletParser {
	
	public static void main(String[] args) {
		long time = System.currentTimeMillis();
		boolean test = usesSpringMvcAnnotations(new File("C:\\test\\projects\\spring-petclinic\\src\\main\\resources\\spring\\mvc-core-config.xml"));
		System.out.println(test);
		System.out.println((System.currentTimeMillis() - time));
	}
	
	// this is much faster than an implementation using the tokenizer.
	public static boolean usesSpringMvcAnnotations(File file) {
		boolean returnValue = false;

		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
		
			String line = reader.readLine();
			while (line != null) {
				if (line.contains("mvc:annotation-driven")) {
					returnValue = true;
					break;
				}
				
				line = reader.readLine();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return returnValue;
	}
}
