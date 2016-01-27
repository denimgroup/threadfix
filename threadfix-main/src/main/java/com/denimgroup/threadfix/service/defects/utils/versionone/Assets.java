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
package com.denimgroup.threadfix.service.defects.utils.versionone;

import javax.xml.bind.annotation.*;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by stran on 3/25/14.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Assets")
public class Assets {

    @XmlElement(name="Asset")
    List<Asset> assets;

    public List<Asset> getAssets() {
        return assets;
    }

    public void setAssets(List<Asset> assets) {
        this.assets = assets;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlRootElement(name="Asset")
    public static class Asset {
        @XmlAttribute(name="href")
        String href;
        @XmlAttribute(name="idref")
        String idref;
        @XmlAttribute(name="id")
        String id;
        @XmlElement(name="Relation")
        List<Relation> relations;
        @XmlElement(name="Attribute")
        List<Attribute> attributes;
        @XmlAttribute(name="act")
        String act;

        public String getAct() {
            return act;
        }

        public void setAct(String act) {
            this.act = act;
        }

        public String getHref() {
            return href;
        }

        public void setHref(String href) {
            this.href = href;
        }

        public String getIdref() {
            return idref;
        }

        public void setIdref(String idref) {
            this.idref = idref;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public List<Relation> getRelations() {
            if (relations == null)
                relations = list();
            return relations;
        }

        public List<String> getRelationNames() {
            List<String> names = list();
            for (Relation relation : getRelations()) {
                if (relation != null) {
                    names.add(relation.getName());
                }
            }
            return names;
        }

        public List<String> getAttributeNames() {
            List<String> names = list();
            for (Attribute attribute : getAttributes()) {
                if (attribute != null) {
                    names.add(attribute.getName());

                }
            }
            return names;
        }

        public Attribute getAttributeByName(String name) {
            if (name == null)
                return null;
            for (Attribute attribute : getAttributes()) {
                if (attribute != null && name.equalsIgnoreCase(attribute.getName())) {
                    return attribute;
                }
            }
            return null;
        }

        public boolean isAssetHasAttr(String name, String value) {
            if (name == null || value == null)
                return false;
            for (Attribute attribute : getAttributes()) {
                if (attribute != null && name.equalsIgnoreCase(attribute.getName())) {
                    for (String v: attribute.getValues())
                        if (value.equalsIgnoreCase(v))
                            return true;
                    for (String v: attribute.getMixed())
                        if (value.equalsIgnoreCase(v))
                            return true;

                    return false;
                }
            }
            return false;
        }

        public void setRelations(List<Relation> relations) {
            this.relations = relations;
        }

        public List<Attribute> getAttributes() {
            if (attributes == null)
                attributes = list();
            return attributes;
        }

        public void setAttributes(List<Attribute> attributes) {
            this.attributes = attributes;
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Relation {
            @XmlElement(name="Asset")
            List<Asset> assetList;
            @XmlAttribute(name="name")
            String name;
            @XmlAttribute(name="act")
            String act;

            public List<Asset> getAssetList() {
                if (assetList == null)
                    assetList = list();
                return assetList;
            }

            public void setAssetList(List<Asset> assetList) {
                this.assetList = assetList;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }
            public String getAct() {
                return act;
            }

            public void setAct(String act) {
                this.act = act;
            }
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Attribute {

            @XmlAttribute(name="name")
            String name;
            @XmlAttribute(name="act")
            String act;
            @XmlElement(name="Value")
            List<String> values = list();
            @XmlMixed
            List<String> mixed = list();

            public List<String> getValues() {
                return values;
            }

            public void setValues(List<String> values) {
                this.values = values;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public List<String> getMixed() {
                return mixed;
            }

            public void setMixed(List<String> mixed) {
                this.mixed = mixed;
            }

            public String getAct() {
                return act;
            }

            public void setAct(String act) {
                this.act = act;
            }

//            public List<String> getValuesAndMixed() {
//                values.addAll(mixed)
//                return getValues().addAll();
//            }
        }
    }
}
