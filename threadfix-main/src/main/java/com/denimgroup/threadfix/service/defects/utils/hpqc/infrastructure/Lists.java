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

/**
 * Created by stran on 3/14/14.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Lists")
public class Lists {
    @XmlElement(name="List")
    List<ListInfo> lists;

    public List<ListInfo> getLists() {
        return lists;
    }

    public void setLists(List<ListInfo> lists) {
        this.lists = lists;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ListInfo {
        @XmlElement(name="Name")
        String name;
        @XmlElement(name="Id")
        String id;
        @XmlElement(name="Items")
        Items items;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public Items getItems() {
            return items;
        }

        public void setItems(Items items) {
            this.items = items;
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Items {
            @XmlElement(name="Item")
            List<Item> itemList;

            public List<Item> getItemList() {
                return itemList;
            }

            public void setItemList(List<Item> itemList) {
                this.itemList = itemList;
            }
        }
        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Item {
            @XmlAttribute(name="value")
            String value;

            @XmlElement(name="Item")
            List<Item> subItemList;

            public String getValue() {
                return value;
            }

            public void setValue(String value) {
                this.value = value;
            }

            public List<Item> getSubItemList() {
                return subItemList;
            }

            public void setSubItemList(List<Item> subItemList) {
                this.subItemList = subItemList;
            }
        }
    }

}
