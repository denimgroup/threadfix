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
package com.denimgroup.threadfix.framework.filefilter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.util.Set;

import org.apache.commons.io.filefilter.IOFileFilter;

import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * This class checks for annotations given by getClassAnnotations before the class
 * definition.
 * @author mcollins
 *
 */
public abstract class ClassAnnotationBasedFileFilter implements IOFileFilter {
	
	private final SanitizedLogger log = new SanitizedLogger("AnnotationBasedFileFilter");
	
	@NotNull
    protected abstract Set<String> getClassAnnotations();
	
	@Override
	public boolean accept(@Nullable File file) {
		boolean returnValue = false;
		boolean hasArroba = false;
		
		if (file != null && file.exists() && file.isFile() && file.getName().endsWith(".java")) {
			try (Reader reader = new FileReader(file)) {
			
				StreamTokenizer tokenizer = new StreamTokenizer(reader);
				tokenizer.slashSlashComments(true);
				tokenizer.slashStarComments(true);
				
				while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
					if (hasArroba && tokenizer.sval != null && getClassAnnotations().contains(tokenizer.sval)) {
						returnValue = true;
						break;
					} else if (tokenizer.sval != null && tokenizer.sval.equals("class")) {
						// we've gone too far
						break;
					}
					
					hasArroba = tokenizer.ttype == '@';
				}
			} catch (IOException e) {
				log.warn("Encountered IOException while tokenizing file.", e);
			}
		}
		
		return returnValue;
	}

	/**
	 * This should just proxy to the other method
	 */
	@Override
	public boolean accept(@NotNull File file, String name) {
		return accept(new File(file.getAbsolutePath() + File.pathSeparator + name));
	}
}
