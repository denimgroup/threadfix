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
package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.framework.impl.rails.model.RailsResource;
import com.denimgroup.threadfix.framework.impl.rails.model.RailsRoute;
import com.denimgroup.threadfix.framework.impl.rails.model.ResourceState;
import com.denimgroup.threadfix.framework.impl.rails.model.ResourceType;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.*;

/**
 * Created by sgerick on 3/9/2015.
 */
public class RailsRoutesParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger("RailsParser");

    private Map<String, RailsRoute> mappings = new HashMap<>();

    private Stack<RailsResource> resourceStack = new Stack<>();
    private RailsResource currentRailsResource = new RailsResource();

    public static Map parse(@Nonnull File file) {
        if (!file.exists()) {
            LOG.error("File not found. Exiting. " + file.getName());
            return null;
        }

        RailsRoutesParser parser = new RailsRoutesParser();
//        System.err.println("stackSizeStart = " + parser.resourceStack.size());
        EventBasedTokenizerRunner.runRails(file, parser);
//        System.err.println("stackSizeEnd = " + parser.resourceStack.size());
        return parser.mappings;
    }


    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        /*
        String charValue = null;
        if (type > 0)
            charValue = String.valueOf(Character.toChars(type));
        */

        /*
        System.err.println();
        System.err.println("line="+lineNumber);
        System.err.println("sTyp="+type);
        System.err.println("sVal="+stringValue);
        System.err.println("cVal="+charValue);
        */

        if (stringValue != null) {
            switch (stringValue.toUpperCase()) {
                case "ROOT":
                case "GET":
                case "MATCH":
                    checkResourcesEnd();
                    currentRailsResource.setResourceType(ResourceType.GET);
                    break;
                case "POST":
                    checkResourcesEnd();
                    currentRailsResource.setResourceType(ResourceType.POST);
                    break;
                case "PUT":
                case "PATCH":
                    checkResourcesEnd();
                    currentRailsResource.setResourceType(ResourceType.PUT);
                    break;
                case "DELETE":
                    checkResourcesEnd();
                    currentRailsResource.setResourceType(ResourceType.DELETE);
                    break;
                case "DO":
                    resourceStack.push(currentRailsResource);
                    currentRailsResource = new RailsResource();
                    break;
                case "IF":
                    checkResourcesEnd();
                    resourceStack.push(currentRailsResource);
                    currentRailsResource = new RailsResource();
                    break;
                case "END":
                    checkResourcesEnd();
                    currentRailsResource = resourceStack.pop();
                    break;
                case "RESOURCE":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.RESOURCE);
                    break;
                case "RESOURCES":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.RESOURCES);
                    break;
                case "COLLECTION":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.COLLECTION);
                    break;
                case "SCOPE":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.SCOPE);
                    break;
                case "MEMBER":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.MEMBER);
                    break;
                case "NAMESPACE":
                    checkResourcesEnd();
                    currentRailsResource = new RailsResource(ResourceType.NAMESPACE);
                    break;
            }
        }

        switch (currentRailsResource.getResourceType()) {
            case GET:
                processUrl("GET", type, stringValue);
                break;
            case POST:
                processUrl("POST", type, stringValue);
                break;
            case PUT:
                processUrl("PUT", type, stringValue);
                break;
            case DELETE:
                processUrl("DELETE", type, stringValue);
                break;
            case RESOURCE:
                processResource(type, stringValue);
                break;
            case RESOURCES:
                processResources(type, stringValue);
                break;
            case NAMESPACE:
                processNamespace(type, stringValue);
                break;
            case COLLECTION:
                processCollection(type, stringValue);
                break;
            case SCOPE:
                processScope(type, stringValue);
                break;
            case MEMBER:
                processMember(type, stringValue);
                break;
        }

    }

    private void checkResourcesEnd() {
        switch (currentRailsResource.getResourceType()) {
            case RESOURCE:
                if (currentRailsResource.getResourceState() ==  ResourceState.DO) {
                    processResource(0, "END");
                }
                break;
            case RESOURCES:
                if (currentRailsResource.getResourceState() ==  ResourceState.DO) {
                    processResources(0, "END");
                }
                break;
        }
    }

    private void processUrl(String method, int type, String stringValue) {
        if (stringValue == null)
            return;
        if (type == StreamTokenizer.TT_WORD && "root".equalsIgnoreCase(stringValue)) {
            stringValue = "";
        }
        else if (type == StreamTokenizer.TT_WORD && stringValue.startsWith(":")
                                            && stringValue.length() > 1) {
            stringValue = stringValue.substring(1);
        } else {
            if (type != DOUBLE_QUOTE && type != '\'')
                return;
        }

        String urlPrefix = "/";
        for (int i = 0; i < resourceStack.size(); i++) {
            ResourceType block = resourceStack.elementAt(i).getResourceType();
            ResourceType nextBlock = null;
            if (i < resourceStack.size() - 1) {
                nextBlock = resourceStack.elementAt(i + 1).getResourceType();
            }
            String urlName = resourceStack.elementAt(i).getUrl();
            if (urlName != null) {
                if (!urlName.isEmpty()) {
                    urlPrefix = urlPrefix + urlName + "/";
                }
                if (ResourceType.RESOURCES.equals(block)
                        && !(ResourceType.COLLECTION.equals(nextBlock))) {
                    urlPrefix = urlPrefix + "{"
                            + resourceStack.elementAt(i).getId()
                            + "}/";
                }
            }

        }

        if (stringValue.startsWith("/") && stringValue.length() > 1) {
            stringValue = stringValue.substring(1);
        }
        String url = urlPrefix + stringValue;

        addMapping(method, url);

        currentRailsResource = new RailsResource(ResourceType.INIT);
    }


    private void processResources(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("PATH:".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.PATH);
        else if ("ONLY:".equalsIgnoreCase(s)) {
            currentRailsResource.initIncludeList();
            currentRailsResource.setResourceState(ResourceState.ONLY);
        }
        else if ("EXCEPT:".equalsIgnoreCase(s)) {
            currentRailsResource.initExcludeList();
            currentRailsResource.setResourceState(ResourceState.EXCEPT);
        }
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);

        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.replaceFirst(":", "");
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case PATH:
                if ((type == DOUBLE_QUOTE || type == '\'')
                        && s.startsWith("/")) {
                    s = s.substring(1);
                    currentRailsResource.setPath(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case ONLY:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    currentRailsResource.addIncludeList(s);
                }
                if (type == ']')
                    currentRailsResource.setResourceState(ResourceState.DO);
                break;
            case EXCEPT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    currentRailsResource.addExcludeList(s);
                }
                if (type == ']')
                    currentRailsResource.setResourceState(ResourceState.DO);
                break;
            case DO:
                break;
            case END:

                String urlPrefix = "/";
                for (int i = 0; i < resourceStack.size(); i++) {
                    ResourceType block = resourceStack.elementAt(i).getResourceType();
                    ResourceType nextBlock = null;
                    if (i < resourceStack.size() - 1) {
                        nextBlock = resourceStack.elementAt(i + 1).getResourceType();
                    }
                    String urlName = resourceStack.elementAt(i).getUrl();
                    if (urlName != null) {
                        if (!urlName.isEmpty()) {
                            urlPrefix = urlPrefix + urlName + "/";
                        }
                        if (ResourceType.RESOURCES.equals(block)
                                && !(ResourceType.COLLECTION.equals(nextBlock))) {
                            urlPrefix = urlPrefix + "{"
                                    + resourceStack.elementAt(i).getId()
                                    + "}/";
                        }
                    }

                }
                if (currentRailsResource.getUrl() != null && !currentRailsResource.getUrl().isEmpty()) {
                        urlPrefix = urlPrefix + currentRailsResource.getUrl() + "/";
                }
                if (urlPrefix.length() > 1) {
                    int endIndex = urlPrefix.lastIndexOf("/");
                    if ((endIndex+1) == urlPrefix.length()) {
                        urlPrefix = urlPrefix.substring(0, endIndex);
                    }
                }
                String id = currentRailsResource.getId();
                if (currentRailsResource.getIncludeList() != null) {
                    // ONLY
                    for (String only : currentRailsResource.getIncludeList()) {
                        switch (only) {
                            case ":index":
                                addMapping("GET", urlPrefix);                   // index
                                break;
                            case ":show":
                                addMapping("GET", urlPrefix + "/{"+id+"}");         // show
                                break;
                            case ":create":
                                addMapping("POST", urlPrefix);                  // create
                                break;
                            case ":new":
                                addMapping("GET", urlPrefix + "/new");          // new
                                break;
                            case ":edit":
                                addMapping("GET", urlPrefix + "/{"+id+"}/edit");    // edit
                                break;
                            case ":update":
                                addMapping("PUT", urlPrefix + "/{"+id+"}");         // update
                                break;
                            case ":destroy":
                                addMapping("DELETE", urlPrefix + "/{"+id+"}");      // destroy
                                break;
                        }
                    }
                } else if (currentRailsResource.getExcludeList() != null) {
                    // EXCEPT
                    if (!currentRailsResource.getExcludeList().contains(":index"))
                        addMapping("GET", urlPrefix);                   // index
                    if (!currentRailsResource.getExcludeList().contains(":show"))
                        addMapping("GET", urlPrefix + "/{"+id+"}");         // show
                    if (!currentRailsResource.getExcludeList().contains(":create"))
                        addMapping("POST", urlPrefix);                  // create
                    if (!currentRailsResource.getExcludeList().contains(":new"))
                        addMapping("GET", urlPrefix + "/new");          // new
                    if (!currentRailsResource.getExcludeList().contains(":edit"))
                        addMapping("GET", urlPrefix + "/{"+id+"}/edit");    // edit
                    if (!currentRailsResource.getExcludeList().contains(":update"))
                        addMapping("PUT", urlPrefix + "/{"+id+"}");         // update
                    if (!currentRailsResource.getExcludeList().contains(":destroy"))
                        addMapping("DELETE", urlPrefix + "/{"+id+"}");      // destroy
                } else {
                    // 7x URLs
                    addMapping("GET", urlPrefix);                   // index
                    addMapping("POST", urlPrefix);                  // create
                    addMapping("GET", urlPrefix + "/new");          // new
                    addMapping("GET", urlPrefix + "/{"+id+"}/edit");    // edit
                    addMapping("GET", urlPrefix + "/{"+id+"}");         // show
                    addMapping("PUT", urlPrefix + "/{"+id+"}");         // update
                    addMapping("DELETE", urlPrefix + "/{"+id+"}");      // destroy
                }

                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }
    }

    private void processResource(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("PATH:".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.PATH);
        else if ("ONLY:".equalsIgnoreCase(s)) {
            currentRailsResource.initIncludeList();
            currentRailsResource.setResourceState(ResourceState.ONLY);
        }
        else if ("EXCEPT:".equalsIgnoreCase(s)) {
            currentRailsResource.initExcludeList();
            currentRailsResource.setResourceState(ResourceState.EXCEPT);
        }
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);

        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.replaceFirst(":", "");
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case PATH:
                if ((type == DOUBLE_QUOTE || type == '\'')
                        && s.startsWith("/")) {
                    s = s.substring(1);
                    currentRailsResource.setPath(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case ONLY:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    currentRailsResource.addIncludeList(s);
                }
                if (type == ']')
                    currentRailsResource.setResourceState(ResourceState.DO);
                break;
            case EXCEPT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    currentRailsResource.addExcludeList(s);
                }
                if (type == ']')
                    currentRailsResource.setResourceState(ResourceState.DO);
                break;
            case DO:
                break;
            case END:

                String urlPrefix = "/";
                for (int i = 0; i < resourceStack.size(); i++) {
                    ResourceType block = resourceStack.elementAt(i).getResourceType();
                    ResourceType nextBlock = null;
                    if (i < resourceStack.size() - 1) {
                        nextBlock = resourceStack.elementAt(i + 1).getResourceType();
                    }
                    String urlName = resourceStack.elementAt(i).getUrl();
                    if (urlName != null) {
                        if (!urlName.isEmpty()) {
                            urlPrefix = urlPrefix + urlName + "/";
                        }
                        if (ResourceType.RESOURCES.equals(block)
                                && !(ResourceType.COLLECTION.equals(nextBlock))) {
                            urlPrefix = urlPrefix + "{"
                                    + resourceStack.elementAt(i).getId()
                                    + "}/";
                        }
                    }

                }
                if (currentRailsResource.getUrl() != null && !currentRailsResource.getUrl().isEmpty()) {
                    urlPrefix = urlPrefix + currentRailsResource.getUrl() + "/";
                }
                if (urlPrefix.length() > 1) {
                    int endIndex = urlPrefix.lastIndexOf("/");
                    if ((endIndex+1) == urlPrefix.length()) {
                        urlPrefix = urlPrefix.substring(0, endIndex);
                    }
                }

                if (currentRailsResource.getIncludeList() != null) {
                    // ONLY
                    for (String only : currentRailsResource.getIncludeList()) {
                        switch (only) {
                            case ":show":
                                addMapping("GET", urlPrefix);           // show
                                break;
                            case ":create":
                                addMapping("POST", urlPrefix);          // create
                                break;
                            case ":new":
                                addMapping("GET", urlPrefix + "/new");  // new
                                break;
                            case ":edit":
                                addMapping("GET", urlPrefix + "/edit"); // edit
                                break;
                            case ":update":
                                addMapping("PUT", urlPrefix);           // update
                                break;
                            case ":destroy":
                                addMapping("DELETE", urlPrefix);        // destroy
                                break;
                        }
                    }
                } else if (currentRailsResource.getExcludeList() != null) {
                    // EXCEPT
                    if (!currentRailsResource.getExcludeList().contains(":show"))
                        addMapping("GET", urlPrefix);           // show
                    if (!currentRailsResource.getExcludeList().contains(":create"))
                        addMapping("POST", urlPrefix);          // create
                    if (!currentRailsResource.getExcludeList().contains(":new"))
                        addMapping("GET", urlPrefix + "/new");  // new
                    if (!currentRailsResource.getExcludeList().contains(":edit"))
                        addMapping("GET", urlPrefix + "/edit"); // edit
                    if (!currentRailsResource.getExcludeList().contains(":update"))
                        addMapping("PUT", urlPrefix);           // update
                    if (!currentRailsResource.getExcludeList().contains(":destroy"))
                        addMapping("DELETE", urlPrefix);        // destroy
                } else {
                    // 6x URLs
                    addMapping("GET", urlPrefix);           // show
                    addMapping("POST", urlPrefix);          // create
                    addMapping("GET", urlPrefix + "/new");  // new
                    addMapping("GET", urlPrefix + "/edit"); // edit
                    addMapping("PUT", urlPrefix);           // update
                    addMapping("DELETE", urlPrefix);        // destroy
                }

                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }   //  end switch
    }

    private void processCollection(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);
        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.replaceFirst(":", "");
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case DO:
                break;
            case END:
                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }
    }

    private void processScope(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("PATH:".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.PATH);
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);
        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if ((type == DOUBLE_QUOTE || type == '\'')
                        && s.startsWith("/")) {
                    s = s.substring(1);
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case PATH:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.substring(1);
                    currentRailsResource.setPath(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case DO:
                break;
            case END:
                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }
    }

    private void processMember(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);
        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.replaceFirst(":", "");
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case DO:
                break;
            case END:
                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }
    }

    private void processNamespace(int type, String s) {
        if ("DO".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.DO);
        else if ("END".equalsIgnoreCase(s))
            currentRailsResource.setResourceState(ResourceState.END);
        switch (currentRailsResource.getResourceState()) {
            case INIT:
                if (type == StreamTokenizer.TT_WORD && s.startsWith(":")) {
                    s = s.replaceFirst(":", "");
                    currentRailsResource.setName(s);
                    currentRailsResource.setResourceState(ResourceState.DO);
                }
                break;
            case DO:
                break;
            case END:
                currentRailsResource = new RailsResource(ResourceType.INIT);
                break;
        }
    }

    private void addMapping(@Nonnull String method, @Nonnull String url) {
        if (url.contains("#{")) {
            url = url.replaceAll("\\#\\{([a-zA-Z_]+)\\}", "{$1}");
        }
        if (url.contains(":")) {
            url = url.replaceAll(":([_a-zA-Z]+)", "{$1}");
        }
        if (url.length() > 1 && url.endsWith("/")) {
            url = url.substring(0, url.length()-1);
        }
        // String m = method + ": " + url;
        RailsRoute route = mappings.get(url);
        if (route == null) {
            route = new RailsRoute(url, method);
        } else {
            route.addHttpMethod(method);
        }
        //mappings.add(m);
        mappings.put(url, route);
    }

}
