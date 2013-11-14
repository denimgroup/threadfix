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

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

// TODO recognize String variables
// TODO support * values:
// from Spring documentation: Ant-style path patterns are supported (e.g. "/myPath/*.do").
class SpringControllerEndpointParser implements EventBasedTokenizer {
	
	@NotNull
    private Set<SpringControllerEndpoint> endpoints = new TreeSet<>();
	private int startLineNumber = 0, curlyBraceCount = 0, lastSymbol = 0;
	private boolean inClass = false;
	@Nullable
    private String classEndpoint = null, currentMapping = null, lastValue = null,
            secondToLastValue = null;

    @NotNull
    private final String rootFilePath;
	@Nullable
    private BeanField currentModelObject = null;
	@NotNull
    private List<String>
		classMethods  = new ArrayList<>(),
		methodMethods = new ArrayList<>(),
		currentParameters = new ArrayList<>();
		
	private static final String
		VALUE = "value",
		METHOD = "method",
		REQUEST_PARAM = "RequestParam",
		PATH_VARIABLE = "PathVariable",
		REQUEST_MAPPING = "RequestMapping",
		CLASS = "class",
		BINDING_RESULT = "BindingResult";
		
	@NotNull
    private Phase phase = Phase.ANNOTATION;
	@NotNull
    private AnnotationState annotationState = AnnotationState.START;
	private SignatureState signatureState = SignatureState.START;
	
	@NotNull
    private SpringEntityMappings entityMappings;
	
	private enum Phase {
		ANNOTATION, SIGNATURE, METHOD
	}
	
	private enum AnnotationState {
		START, ARROBA, REQUEST_MAPPING, VALUE, METHOD, METHOD_MULTI_VALUE, ANNOTATION_END
	}
	
	private enum SignatureState {
		START, ARROBA, REQUEST_PARAM
	}
	
	@NotNull
    public static Set<SpringControllerEndpoint> parse(@NotNull File file, @NotNull SpringEntityMappings entityMappings) {
		SpringControllerEndpointParser parser = new SpringControllerEndpointParser(file.getAbsolutePath(), entityMappings);
		EventBasedTokenizerRunner.run(file, parser);
		return parser.endpoints;
	}
	
	private SpringControllerEndpointParser(@NotNull String rootFilePath,
                                           @NotNull SpringEntityMappings entityMappings) {
		this.rootFilePath = rootFilePath;
		this.entityMappings = entityMappings;
	}
	
	@Override
	public void processToken(int type, int lineNumber, String stringValue) {
		switch (phase) {
			case ANNOTATION: parseAnnotation(type, lineNumber, stringValue); break;
			case SIGNATURE:  parseSignature(type, stringValue);  break;
			case METHOD:     parseMethod(type, lineNumber);     break;
		}
	}
	
	private void setState(SignatureState state) {
		signatureState = state;
	}
	
	private void parseSignature(int type, @Nullable String stringValue) {
		
		if (lastSymbol == CLOSE_PAREN && type == OPEN_CURLY) {
			curlyBraceCount = 1;
			phase = Phase.METHOD;
		} else {
			lastSymbol = type;
		}
		
		switch (signatureState) {
			case START:
				if (type == ARROBA) {
					setState(SignatureState.ARROBA);
				} else if (stringValue != null && stringValue.equals(BINDING_RESULT) &&
                        secondToLastValue != null && lastValue != null) {
					currentModelObject = new BeanField(secondToLastValue, lastValue); // should be type and variable name
				}
				break;
			case ARROBA:
				if (stringValue != null &&
						(stringValue.equals(REQUEST_PARAM) || stringValue.equals(PATH_VARIABLE))) {
					setState(SignatureState.REQUEST_PARAM);
				} else {
					setState(SignatureState.START);
				}
				break;
			case REQUEST_PARAM:
				if (type == DOUBLE_QUOTE) {
					currentParameters.add(stringValue);
				} else if (type != COMMA && type != CLOSE_PAREN) {
					lastValue = stringValue;
				} else if (type == COMMA) {
					currentParameters.add(lastValue);
					lastValue = null;
					setState(SignatureState.START);
				} else { // type must be CLOSE_PAREN
					if (lastValue != null) {
						currentParameters.add(lastValue);
						lastValue = null;
					}
				}
				break;
		}
		if (stringValue != null) {
			secondToLastValue = lastValue;
			lastValue = stringValue;
		}
	}

	private void parseMethod(int type, int lineNumber) {
		if (type == OPEN_CURLY) {
			curlyBraceCount += 1;
		} else if (type == CLOSE_CURLY) {
			if (curlyBraceCount == 1) {
				addEndpoint(lineNumber);
				signatureState = SignatureState.START;
				phase = Phase.ANNOTATION;
			} else {
				curlyBraceCount -= 1;
			}
		}
	}

	private void parseAnnotation(int type, int lineNumber, @Nullable String stringValue) {
		switch(annotationState) {
			case START:
				if (type == ARROBA) {
					annotationState = AnnotationState.ARROBA;
				} else if (stringValue != null && stringValue.equals(CLASS)) {
					inClass = true;
				}
				break;
			case ARROBA:
				if (stringValue != null && stringValue.equals(REQUEST_MAPPING)) {
					annotationState = AnnotationState.REQUEST_MAPPING;
				} else {
					annotationState = AnnotationState.START;
				}
				break;
			case REQUEST_MAPPING:
				if (stringValue != null && stringValue.equals(VALUE)) {
					annotationState = AnnotationState.VALUE;
				} else if (stringValue != null && stringValue.equals(METHOD)) {
					annotationState = AnnotationState.METHOD;
				} else if (type == DOUBLE_QUOTE) {
					// If it immediately starts with a quoted value, use it
					if (inClass) {
						currentMapping = stringValue;
						startLineNumber = lineNumber;
						annotationState = AnnotationState.ANNOTATION_END;
					} else {
						classEndpoint = stringValue;
						annotationState = AnnotationState.START;
					}
				} else if (type == CLOSE_PAREN){
					annotationState = AnnotationState.ANNOTATION_END;
				}
				break;
			case VALUE:
				if (stringValue != null) {
					if (inClass) {
						currentMapping = stringValue;
						startLineNumber = lineNumber;
					} else {
						classEndpoint = stringValue;
					}
					annotationState = AnnotationState.REQUEST_MAPPING;
				}
				break;
			case METHOD:
				if (stringValue != null) {
					if (inClass) {
						methodMethods.add(stringValue);
					} else {
						classMethods.add(stringValue);
					}
					annotationState = AnnotationState.REQUEST_MAPPING;
				} else if (type == OPEN_CURLY){
					annotationState = AnnotationState.METHOD_MULTI_VALUE;
				}
				break;
			case METHOD_MULTI_VALUE:
				if (stringValue != null) {
					if (inClass) {
						methodMethods.add(stringValue);
					} else {
						classMethods.add(stringValue);
					}
				} else if (type == CLOSE_CURLY) {
					annotationState = AnnotationState.REQUEST_MAPPING;
				}
				break;
			case ANNOTATION_END:
				if (inClass) {
					annotationState = AnnotationState.START;
					phase = Phase.SIGNATURE;
				} else {
					annotationState = AnnotationState.START;
				}
				break;
		}
	}

	private void addEndpoint(int endLineNumber) {
		if (classEndpoint != null) {
			if (currentMapping != null) {
				currentMapping = classEndpoint + currentMapping;
			} else {
				currentMapping = classEndpoint;
			}
		}
		
		// It's ok to add a default method here because we must be past the class-level annotation
		if (classMethods.isEmpty()) {
			classMethods.add("RequestMethod.GET");
		}
		
		if (methodMethods.isEmpty()) {
			methodMethods.addAll(classMethods);
		}
		
		if (currentModelObject != null) {
			
			BeanFieldSet fields = entityMappings.getPossibleParametersForModelType(currentModelObject.getType());
			
			currentParameters.addAll(fields.getPossibleParameters());
			currentModelObject = null;
		}
		
		endpoints.add(new SpringControllerEndpoint(rootFilePath, currentMapping,
				methodMethods, currentParameters,
				startLineNumber, endLineNumber));
		currentMapping = null;
		methodMethods = new ArrayList<>();
		startLineNumber = -1;
		curlyBraceCount = 0;
		currentParameters = new ArrayList<>();
	}
	
}
