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
package com.denimgroup.threadfix.framework;

import javax.annotation.Nonnull;

import java.io.File;

import static org.junit.Assert.assertTrue;

public class ResourceManager {

	@Nonnull
    public static File getFile(String name) {
		File file = new File(TestConstants.THREADFIX_SOURCE_ROOT + "threadfix-ham/target/test-classes/" + name);
        assertTrue("File " + file.getAbsolutePath() + " didn't exist. Please fix your configuration.", file.exists());

        return file;
    }

	@Nonnull
    public static File getSpringFile(String name) {
		return getFile("code/spring/" + name);
	}

    @Nonnull
    public static File getDotNetMvcFile(String name) {
        return getFile("code.dotNet.mvc/" + name);
    }

    @Nonnull
    public static File getDotNetWebFormsFile(String name) {
        return getFile("code.dotNet.webforms/" + name);
    }

    @Nonnull
    public static File getRailsFile(String name) {
        return getFile("code.rails/" + name);
    }
}