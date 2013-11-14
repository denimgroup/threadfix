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
package com.denimgroup.threadfix.framework.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;


/**
 * This class abstracts all of the exception catching and logging and opening up a
 * file reader on the given file.
 * 
 * <p>See also: {@link EventBasedTokenizer}
 * <p>See also: {@link EventBasedTokenizerRunner#run}
 * @author mcollins
 *
 */
public class EventBasedTokenizerRunner {

	private static final SanitizedLogger log = new SanitizedLogger("EventBasedTokenizerRunner");
	
	/**
	 * The default idiom for parsing and getting results using this
	 * class is
	 * 
	 * <code>
	 *  <p>EventBasedTokenizer parser = new EventBasedTokenizer();
	 *	<p>EventBasedTokenizerRunner.run(file, parser);
	 *  <p>return parser.results;
	 * </code>
	 * @param file
	 * @param eventTokenizer
	 */
	public static void run(@Nullable File file, @NotNull EventBasedTokenizer eventTokenizer) {

		if (file != null && file.exists() && file.isFile()) {
			try (Reader reader = new FileReader(file)) {
			
				StreamTokenizer tokenizer = new StreamTokenizer(reader);
				tokenizer.slashSlashComments(true);
				tokenizer.slashStarComments(true);
				tokenizer.ordinaryChar('<');
				tokenizer.wordChars(':', ':');
				
				while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
					eventTokenizer.processToken(tokenizer.ttype, tokenizer.lineno(), tokenizer.sval);
				}
				
			} catch (FileNotFoundException e) {
				// shouldn't happen, we check to make sure it exists
				log.error("Encountered FileNotFoundException while looking for file", e);
			} catch (IOException e) {
				log.warn("Encountered IOException while tokenizing file.", e);
			}
		}
	}
}
