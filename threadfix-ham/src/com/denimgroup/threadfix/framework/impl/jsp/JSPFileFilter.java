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
package com.denimgroup.threadfix.framework.impl.jsp;

import java.io.File;

import org.apache.commons.io.filefilter.IOFileFilter;
import org.jetbrains.annotations.NotNull;

class JSPFileFilter implements IOFileFilter {
	
	public static final JSPFileFilter INSTANCE = new JSPFileFilter();
	private JSPFileFilter(){}
	
	@Override
	public boolean accept(@NotNull File file) {
		return file.getName().contains(".jsp");
	}
	@Override
	public boolean accept(File dir, @NotNull String name) {
		return name.contains(".jsp");
	}
}