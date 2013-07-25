package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.util.HashSet;
import java.util.Set;

import com.denimgroup.threadfix.service.SanitizedLogger;

public class SpringControllerEndpointParser {
	
	enum State {
		START, ARROBA, REQUEST_MAPPING, VALUE, END_PAREN, END_CURLY;
	}
	
	private static final SanitizedLogger log = new SanitizedLogger("SpringControllerEndpointParser");
	
	private SpringControllerEndpointParser(){}
	
	public static Set<SpringControllerEndpoint> parseEndpoints(File file) {
		State state = State.START;
		String mapping = null;
		int startLineNumber = 0, curlyBraceCount = 0;
		
		Set<SpringControllerEndpoint> endpoints = new HashSet<>();
		
		if (file != null && file.exists() && file.isFile() && file.getName().endsWith(".java")) {
			Reader reader = null;
			
			try {
				reader = new FileReader(file);
			
				StreamTokenizer tokenizer = new StreamTokenizer(reader);
				tokenizer.slashSlashComments(true);
				tokenizer.slashStarComments(true);
				
				while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
					switch(state) {
						case START: 
							if (tokenizer.ttype == '@') {
								state = State.ARROBA;
							}
							break;
						case ARROBA:
							if (tokenizer.sval != null && tokenizer.sval.equals("RequestMapping")) {
								state = State.REQUEST_MAPPING;
							} else {
								state = State.ARROBA;
							}
							break;
						case REQUEST_MAPPING:
							if (tokenizer.sval != null && tokenizer.sval.equals("value")) {
								state = State.VALUE;
							} else if (tokenizer.ttype == ')'){
								state = State.END_PAREN;
							}
							break;
						case END_PAREN:
							// TODO implement class defaults parsing
							break;
						case VALUE:
							if (tokenizer.sval != null) {
								mapping = tokenizer.sval;
								startLineNumber = tokenizer.lineno();
								state = State.END_CURLY;
							}
							break;
						case END_CURLY:
							if (tokenizer.ttype == '{') {
								curlyBraceCount += 1;
								
							} else if (tokenizer.ttype == '}') {
								if (curlyBraceCount == 1) {
									endpoints.add(new SpringControllerEndpoint(
											file.getAbsolutePath(), mapping, startLineNumber, tokenizer.lineno()));
									mapping = null;
									startLineNumber = -1;
									curlyBraceCount = 0;
									state = State.START;
								} else {
									curlyBraceCount -= 1;
								}
							}
							break;
					}
				}
			} catch (FileNotFoundException e) {
				// shouldn't happen, we check to make sure it exists
				log.error("Encountered FileNotFoundException while looking for @Controllers", e);
			} catch (IOException e) {
				log.warn("Encountered IOException while tokenizing file.", e);
			} finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (IOException e) {
						log.error("IOException encountered while trying to close the FileReader.");
					}
				}
			}
		}
		
		return endpoints;
	}
	
}
