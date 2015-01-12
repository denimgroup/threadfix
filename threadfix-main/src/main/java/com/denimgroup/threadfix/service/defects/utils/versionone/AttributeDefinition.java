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
package com.denimgroup.threadfix.service.defects.utils.versionone;

import com.denimgroup.threadfix.CollectionUtils;
import org.xml.sax.Attributes;

import java.util.List;

/**
 * Created by mac on 7/7/14.
 */
public class AttributeDefinition {

    public static final String REQUIRED_KEY = "isrequired", TYPE_KEY = "attributetype", NAME_KEY = "name", MULTI_VALUE_KEY = "ismultivalue",
            READONLY_KEY = "isreadonly", CUSTOM_KEY = "iscustom";

    final boolean required;

    public boolean isMultiValue() {
        return isMultiValue;
    }

    final boolean isMultiValue, isReadOnly, isCustom;
    final String  relationType, name;
    String relatedItemType = null;
    List<Assets.Asset> assetList = CollectionUtils.list();

    public AttributeDefinition(Attributes attributes) {

        String requiredString = attributes.getValue(REQUIRED_KEY),
                multiValueString = attributes.getValue(MULTI_VALUE_KEY),
                readOnlyString = attributes.getValue(READONLY_KEY),
                customString = attributes.getValue(CUSTOM_KEY);

        required = requiredString != null && requiredString.equals("True");
        isMultiValue = multiValueString != null && multiValueString.equals("True");
        relationType = attributes.getValue(TYPE_KEY);
        name = attributes.getValue(NAME_KEY);
        isReadOnly = readOnlyString != null && readOnlyString.equals("True");
        isCustom = customString != null && customString.equals("True");
    }

    public boolean isRequired() {
        return required;
    }

    public String getRelationType() {

        switch (relationType) {
            case "Text":
            case "Password":
            case "LongText":
               return "textarea";
            case "Relation":
                return "select";
            case "Numeric":
                return "number";
            case "LongInt":
                return "number";
            case "Rank":
                return "number";
            case "Date":
            default:
        }

        return relationType;
    }

    public String getName() {
        return name;
    }

    public String getRelatedItemType() {
        return relatedItemType;
    }

    public void setRelatedItemType(String relatedItemType) {
        this.relatedItemType = relatedItemType;
    }

    public boolean isReadOnly() {
        return isReadOnly;
    }

    public boolean isCustom() {
        return isCustom;
    }

    public List<Assets.Asset> getAssetList() {
        return assetList;
    }

    public void setAssetList(List<Assets.Asset> assetList) {
        this.assetList = assetList;
    }

    @Override
    public String toString() {
        return "AttributeDefinition{" +
                "required=" + required +
                ", isMultiValue=" + isMultiValue +
                ", isReadOnly=" + isReadOnly +
                ", isCustom=" + isCustom +
                ", relationType='" + relationType + '\'' +
                ", name='" + name + '\'' +
                ", relatedItemType='" + relatedItemType + '\'' +
                '}';
    }
}
