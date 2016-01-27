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

package com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure;

import javax.xml.bind.annotation.*;
import java.util.List;
import java.util.Map;

/**
 * Created by stran on 7/03/14.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Fields")
public class Fields {
    @XmlElement(name="Field")
    List<Field> fields;

    public List<Field> getFields() {
        return fields;
    }

    public void setFields(List<Field> fields) {
        this.fields = fields;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Field {
        @XmlAttribute(name = "PhysicalName")
        String physicalName;
        @XmlAttribute(name = "Name")
        String name;
        @XmlAttribute(name = "Label")
        String label;

        @XmlElement(name="Size")
        int size;
        @XmlElement(name="List-Id")
        String listId;
        @XmlElement(name="Required")
        boolean required;
        @XmlElement(name="Type")
        String type;
        @XmlElement(name="Active")
        boolean active;
        @XmlElement(name="Editable")
        boolean editable;
        @XmlElement(name="References")
        References references;
        @XmlElement(name="SupportsMultivalue")
        boolean supportsMultivalue;


        public String getPhysicalName() {
            return physicalName;
        }

        public void setPhysicalName(String physicalName) {
            this.physicalName = physicalName;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public int getSize() {
            return size;
        }

        public void setSize(int size) {
            this.size = size;
        }

        public String getListId() {
            return listId;
        }

        public void setListId(String listId) {
            this.listId = listId;
        }

        public boolean isRequired() {
            return required;
        }

        public void setRequired(boolean required) {
            this.required = required;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

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

        public References getReferences() {
            return references;
        }

        public void setReferences(References references) {
            this.references = references;
        }

        public boolean isSupportsMultivalue() {
            return supportsMultivalue;
        }

        public void setSupportsMultivalue(boolean supportsMultivalue) {
            this.supportsMultivalue = supportsMultivalue;
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class References {
            @XmlElement(name="RelationReference")
            List<RelationReference> relationReferences;

            public List<RelationReference> getRelationReferences() {
                return relationReferences;
            }

            public void setRelationReferences(List<RelationReference> relationReferences) {
                this.relationReferences = relationReferences;
            }
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class RelationReference {
            @XmlAttribute(name = "RelationName")
            String relationName;
            @XmlAttribute(name = "ReferencedEntityType")
            String referencedEntityType;

            public String getRelationName() {
                return relationName;
            }

            public void setRelationName(String relationName) {
                this.relationName = relationName;
            }

            public String getReferencedEntityType() {
                return referencedEntityType;
            }

            public void setReferencedEntityType(String referencedEntityType) {
                this.referencedEntityType = referencedEntityType;
            }
        }
    }

}
