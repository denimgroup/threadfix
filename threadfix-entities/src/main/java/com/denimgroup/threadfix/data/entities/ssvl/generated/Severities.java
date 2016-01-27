////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.08.03 at 05:23:08 PM CDT 
//


package com.denimgroup.threadfix.data.entities.ssvl.generated;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Severities.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="Severities">
 *   &lt;restriction base="{}Severity">
 *     &lt;enumeration value="Critical"/>
 *     &lt;enumeration value="High"/>
 *     &lt;enumeration value="Medium"/>
 *     &lt;enumeration value="Low"/>
 *     &lt;enumeration value="Info"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "Severities")
@XmlEnum
public enum Severities {

    @XmlEnumValue("Critical")
    CRITICAL("Critical"),
    @XmlEnumValue("High")
    HIGH("High"),
    @XmlEnumValue("Medium")
    MEDIUM("Medium"),
    @XmlEnumValue("Low")
    LOW("Low"),
    @XmlEnumValue("Info")
    INFO("Info");
    private final String value;

    Severities(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static Severities fromValue(String v) {
        for (Severities c: Severities.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
