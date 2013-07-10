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
package com.denimgroup.threadfix.service;

import java.util.HashSet;
import java.util.Set;

/**
 * This class is used to hold information about what types of algorithms to use in a vulnerability merge.
 * 
 * @author mcollins
 *
 */
public class ScanMergeConfiguration {
	
	public ScanMergeConfiguration(TypeStrategy typeStrategy, 
			PathStrategy pathStrategy,
			ParameterStrategy parameterStrategy) {
		this.typeStrategy      = typeStrategy;
		this.parameterStrategy = parameterStrategy;
		this.pathStrategy      = pathStrategy;
	}
	
	public final TypeStrategy typeStrategy;
	public final PathStrategy pathStrategy;
	public final ParameterStrategy parameterStrategy;
	
	enum TypeStrategy {
		BASIC, TREES, FAULT_PATTERN
	}

	enum PathStrategy {
		BASIC, GUESS_ROOT, USER_ASSISTED, SOURCE_CODE
	}

	enum ParameterStrategy {
		BASIC, USER_ASSISTED
	}
	
	public static ScanMergeConfiguration getBasicConfiguration() {
		return new ScanMergeConfiguration(
				TypeStrategy.BASIC, PathStrategy.BASIC, ParameterStrategy.BASIC);
	}

	public static Set<ScanMergeConfiguration> getAllPermutations() {
		Set<ScanMergeConfiguration> configurations = new HashSet<>();
		
		for (TypeStrategy typeStrategy : TypeStrategy.values()) {
			for (PathStrategy pathStrategy : PathStrategy.values()) {
				for (ParameterStrategy parameterStrategy : ParameterStrategy.values()) {
					configurations.add(new ScanMergeConfiguration(typeStrategy, pathStrategy, parameterStrategy));
				}
			}
		}
		
		return configurations;
	}
}
