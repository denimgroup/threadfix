////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.util.java;

import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

public class EntityParser implements EventBasedTokenizer {

    @Nonnull
    private Set<ModelField> fieldMappings = set();

    @Nonnull
    private List<String> publicMethods = list();

    @Nullable
    private String          className     = null, superClass = null, currentParamType = null;

    @Nonnull
    public static EntityParser parse(@Nonnull File file) {
        EntityParser parser = new EntityParser();
        EventBasedTokenizerRunner.run(file, parser);
        return parser;
    }

    enum State {
        START, CLASS, EXTENDS, PUBLIC, PARAM_TYPE
    }

    @Nonnull
    private State state = State.START;

    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
    public void processToken(int type, int lineNumber, @Nullable String stringValue) {
        switch (state) {
            case START:
                if ("extends".equals(stringValue)) {
                    state = State.EXTENDS;
                } else if ("public".equals(stringValue)) {
                    state = State.PUBLIC;
                } else if (className == null && "class".equals(stringValue)) {
                    state = State.CLASS;
                }
                break;
            case CLASS:
                if (stringValue != null) {
                    className = stringValue;
                }
                state = State.START;
                break;
            case EXTENDS:
                if (stringValue != null) {
                    superClass = stringValue;
                }
                state = State.START;
                break;
            case PUBLIC:
                if (className == null && "class".equals(stringValue)) {
                    state = State.CLASS;
                } else if (stringValue != null) {
                    currentParamType = stringValue;
                    state = State.PARAM_TYPE;
                } else {
                    state = State.START;
                }
                break;
            case PARAM_TYPE:
                if (currentParamType != null && stringValue != null && stringValue.startsWith("get") &&
                        stringValue.length() > 3) { // this is to avoid errors with methods named "get"
				    fieldMappings.add(new ModelField(currentParamType, stringValue));
			    }
                if (currentParamType != null && stringValue != null && !stringValue.startsWith("get")
                    && stringValue.length() > 0 && currentParamType.equals("String")) { // public String method()
                        publicMethods.add(stringValue);
                }
			    state = State.START;
			    break;
		}
	}

	@Nonnull
    public Set<ModelField> getFieldMappings() {
		return fieldMappings;
	}

    @Nonnull
    public List<String> getMethods() {
        return publicMethods;
    }

    @Nullable
    public String getClassName() {
		return className;
	}

	@Nullable
    public String getSuperClass() {
		return superClass;
	}
}
