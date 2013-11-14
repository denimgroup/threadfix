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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.denimgroup.threadfix.framework.filefilter.ClassAnnotationBasedFileFilter;
import org.jetbrains.annotations.NotNull;

/**
 * This class can be used with Commons FileUtils to filter for finding Spring @Controllers.
 *
 * It actually just finds any file with an uncommented @Controller in it.
 * 
 * @author mcollins
 *
 */
class SpringControllerFileFilter extends ClassAnnotationBasedFileFilter {
	
	private SpringControllerFileFilter(){}
	
	public static final SpringControllerFileFilter INSTANCE = new SpringControllerFileFilter();
	
	private static final Set<String> annotations = new HashSet<>(Arrays.asList("Controller"));
	
	@NotNull
    @Override
	protected Set<String> getClassAnnotations() {
		return annotations;
	}
}
