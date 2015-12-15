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

package com.denimgroup.threadfix.viewmodels;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by stran on 7/10/14.
 */
public class DynamicFormField {
    String name;
    String label;
    String placeholder;
    String validate;
    String typeAheadUrl;
    Object value;

    int maxLength;
    int minLength;
    Integer minValue, maxValue;
    boolean required;
    String type;
    boolean active;
    boolean editable;
    boolean supportsMultivalue;
    String show;
    String step;

    Map<String, String> optionsMap;
    Map<String, String> errorsMap;

    public String getValidate() {
        return validate;
    }

    public void setValidate(String validate) {
        this.validate = validate;
    }

    public Map<String, String> getErrorsMap() {
        return errorsMap;
    }

    public void setErrorsMap(Map<String, String> errorsMap) {
        this.errorsMap = errorsMap;
    }

    public void setError(String key, String value) {
        if (errorsMap == null) {
            errorsMap = map();
        }

        errorsMap.put(key, value);
    }

    public String getPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @JsonView(AllViews.RestView2_1.class)
    public String getTypeAheadUrl() {
        return typeAheadUrl;
    }

    public void setTypeAheadUrl(String typeAheadUrl) {
        this.typeAheadUrl = typeAheadUrl;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public int getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
        this.setError("maxlength", "Input up to " + maxLength +" characters only.");
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public int getMinLength() {
        return minLength;
    }

    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
        if (required)
            this.setError("required", "This field cannot be empty.");
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
        if ("number".equals(type)) {
            this.setError("number", "Not valid number.");
        }
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isEditable() {
        return editable;
    }

    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    /**
     * the key is the value of the option tag and the value is what gets displayed.
     * @return
     */
    @JsonView(AllViews.RestViewScan2_1.class)
    public Map<String, String> getOptionsMap() {
        return optionsMap;
    }

    public void setOptionsMap(Map<String, String> optionsMap) {
        this.optionsMap = sortByValues(optionsMap);
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public boolean isSupportsMultivalue() {
        return supportsMultivalue;
    }

    public void setSupportsMultivalue(boolean supportsMultivalue) {
        this.supportsMultivalue = supportsMultivalue;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public String getShow() {
        return show;
    }

    public void setShow(String show) {
        this.show = show;
    }

    /*
         * Java method to sort Map in Java by value e.g. HashMap or Hashtable
         * It also sort values even if they are duplicates
         */
    public static <K extends Comparable<K>,V extends Comparable<V>> Map<K,V> sortByValues(Map<K,V> map){
        if (map == null)
            return null;
        List<Map.Entry<K,V>> entries = new LinkedList<Map.Entry<K, V>>(map.entrySet());

        Collections.sort(entries, new Comparator<Map.Entry<K, V>>() {

            @Override
            public int compare(Map.Entry<K, V> o1, Map.Entry<K, V> o2) {
                return o1.getValue().compareTo(o2.getValue());
            }
        });

        //LinkedHashMap will keep the keys in the order they are inserted
        //which is currently sorted on natural ordering
        Map<K,V> sortedMap = new LinkedHashMap<K, V>();

        for(Map.Entry<K,V> entry: entries){
            sortedMap.put(entry.getKey(), entry.getValue());
        }

        return sortedMap;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public String getStep() {
        return step;
    }

    public void setStep(String step) {
        this.step = step;
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public Integer getMinValue() {
        return minValue;
    }

    public void setMinValue(Integer minValue) {
        this.minValue = minValue;
        this.setError("min", "Input min is " + minValue + ".");
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public Integer getMaxValue() {
        return maxValue;
    }

    public void setMaxValue(Integer maxValue) {
        this.maxValue = maxValue;
        this.setError("max", "Input max is " + maxValue + ".");
    }

    @JsonView(AllViews.RestViewScan2_1.class)
    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
