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
package com.denimgroup.threadfix.data.enums;

import com.fasterxml.jackson.annotation.JsonView;

public enum TagType {
    APPLICATION("Application"),
    VULNERABILITY("Vulnerability"),
    COMMENT("Vulnerability Comment");

    TagType(String displayName) {
        this.displayName = displayName;
    }

    private String displayName;

    @JsonView(Object.class)
    public String getDisplayName() { return displayName; }

    public static TagType getTagType(String input) {
        TagType type = null;

        if (input != null) {
            for (TagType tagType : values()) {
                if (tagType.toString().equals(input) ||
                        tagType.displayName.equals(input)) {
                    type = tagType;
                    break;
                }
            }
        }

        return type;
    }
}