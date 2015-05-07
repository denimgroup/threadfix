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
package com.denimgroup.threadfix.framework.impl.rails.model;

import java.util.List;
import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 4/8/2015.
 */
public class RailsResource {
    private ResourceType resourceType;
    private ResourceState resourceState;
    private String name;
    private String path;
    private List<String> includeList;
    private List<String> excludeList;
//    private boolean hasId;

    public RailsResource() {
        this.resourceType = ResourceType.INIT;
        this.resourceState = ResourceState.INIT;
    }

    public RailsResource(ResourceType type) {
        this.resourceType = type;
        this.resourceState = ResourceState.INIT;
    }


    public ResourceType getResourceType() {
        return resourceType;
    }

    public void setResourceType(ResourceType resourceType) {
        this.resourceType = resourceType;
    }


    public ResourceState getResourceState() {
        return resourceState;
    }

    public void setResourceState(ResourceState resourceState) {
        this.resourceState = resourceState;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public List<String> getIncludeList() {
        return includeList;
    }

    public void initIncludeList() {
        this.includeList = list();
    }

//    public void setIncludeList(List<String> includeList) {
//        this.includeList = includeList;
//    }

    public void addIncludeList(String includeItem) {
//        if (this.includeList == null) {
//            this.includeList = new ArrayList<>();
//        }
        this.includeList.add(includeItem);
    }

    public List<String> getExcludeList() {
        return excludeList;
    }

    public void initExcludeList() {
        this.excludeList = list();
    }

//    public void setExcludeList(List<String> excludeList) {
//        this.excludeList = excludeList;
//    }

    public void addExcludeList(String excludeItem) {
//        if (this.excludeList == null) {
//            this.excludeList = new ArrayList<>();
//        }
        this.excludeList.add(excludeItem);
    }

//    public boolean hasId() {
//        return hasId;
//    }
//
//    public void setHasId(boolean hasId) {
//        this.hasId = hasId;
//    }

    public String getId() {
        String id = "id";
        String url = getName();
        if (url.length() > 1 && url.toLowerCase().endsWith("s")) {
            id = url.substring(0, url.length()-1);
            id = id.concat("_id");
        }
        return id;
    }

    public String getUrl() {
        String url = this.getPath();
        if (url != null) {
            if (url.startsWith("/")) {
                url = url.substring(1);
            }
        } else {
            url = this.getName();
        }
        return url;
    }


}
