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
		START, ARROBA, REQUEST_MAPPING, VALUE, END_PAREN
	}
	
	private static final SanitizedLogger log = new SanitizedLogger("SpringControllerEndpointParser");
	
	private SpringControllerEndpointParser(){}
	
	public static Set<String> parseEndpoints(File file) {
		State state = State.START;
		
		Set<String> endpoints = new HashSet<>();
		
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
						case VALUE:
							if (tokenizer.sval != null) {
								endpoints.add(tokenizer.sval);
								state = State.START;
							}
							break;
						case END_PAREN:
							endpoints.add("/");
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
