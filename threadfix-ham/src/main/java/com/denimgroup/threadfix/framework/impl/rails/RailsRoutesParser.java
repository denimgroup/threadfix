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

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by sgerick on 3/9/2015.
 */
public class RailsRoutesParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger("RailsParser");

    private Map<String, RailsRoute> mappings = map();

    private Stack<RailsResource> resourceStack = new Stack<RailsResource>();
    private RailsResource currentRailsResource = new RailsResource();

    public static Map parse(@Nonnull File file) {
        if (!file.exists()) {
            LOG.error("File not found. Exiting. " + file.getName());
            return null;
        }

        RailsRoutesParser parser = new RailsRoutesParser();
        EventBasedTokenizerRunner.runRails(file, parser);
        return parser.mappings;
    }


    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        if (stringValue != null) {
            String s = stringValue.toUpperCase();
            if (s.equals("ROOT") || s.equals("GET") || s.equals("MATCH")) {
                checkResourcesEnd();
                currentRailsResource.setResourceType(ResourceType.GET);

            } else if (s.equals("POST")) {
                checkResourcesEnd();
                currentRailsResource.setResourceType(ResourceType.POST);

            } else if (s.equals("PUT") || s.equals("PATCH")) {
                checkResourcesEnd();
                currentRailsResource.setResourceType(ResourceType.PUT);

            } else if (s.equals("DELETE")) {
                checkResourcesEnd();
                currentRailsResource.setResourceType(ResourceType.DELETE);

            } else if (s.equals("DO")) {
                resourceStack.push(currentRailsResource);
                currentRailsResource = new RailsResource();

            } else if (s.equals("IF")) {
                checkResourcesEnd();
                resourceStack.push(currentRailsResource);
                currentRailsResource = new RailsResource();

            } else if (s.equals("END")) {
                checkResourcesEnd();
                currentRailsResource = resourceStack.pop();

            } else if (s.equals("RESOURCE")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.RESOURCE);

            } else if (s.equals("RESOURCES")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.RESOURCES);

            } else if (s.equals("COLLECTION")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.COLLECTION);

            } else if (s.equals("SCOPE")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.SCOPE);

            } else if (s.equals("MEMBER")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.MEMBER);

            } else if (s.equals("NAMESPACE")) {
                checkResourcesEnd();
                currentRailsResource = new RailsResource(ResourceType.NAMESPACE);

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
//                    urlPrefix = urlPrefix + "{"
//                            + resourceStack.elementAt(i).getId()
//                            + "}/";
                    urlPrefix += "{id}/";
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
//                            urlPrefix = urlPrefix + "{"
//                                    + resourceStack.elementAt(i).getId()
//                                    + "}/";
                            urlPrefix += "{id}/";

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
                String id = "id";
                if (currentRailsResource.getIncludeList() != null) {
                    // ONLY
                    for (String only : currentRailsResource.getIncludeList()) {
                        if (only.equals(":index")) {
                            addMapping("GET", urlPrefix);                   // index

                        } else if (only.equals(":show")) {
                            addMapping("GET", urlPrefix + "/{" + id + "}");         // show

                        } else if (only.equals(":create")) {
                            addMapping("POST", urlPrefix);                  // create

                        } else if (only.equals(":new")) {
                            addMapping("GET", urlPrefix + "/new");          // new

                        } else if (only.equals(":edit")) {
                            addMapping("GET", urlPrefix + "/{" + id + "}/edit");    // edit

                        } else if (only.equals(":update")) {
                            addMapping("PUT", urlPrefix + "/{" + id + "}");         // update

                        } else if (only.equals(":destroy")) {
                            addMapping("DELETE", urlPrefix + "/{" + id + "}");      // destroy

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
//                            urlPrefix = urlPrefix + "{"
//                                    + resourceStack.elementAt(i).getId()
//                                    + "}/";
                            urlPrefix += "{id}/";

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
                        if (only.equals(":show")) {
                            addMapping("GET", urlPrefix);           // show

                        } else if (only.equals(":create")) {
                            addMapping("POST", urlPrefix);          // create

                        } else if (only.equals(":new")) {
                            addMapping("GET", urlPrefix + "/new");  // new

                        } else if (only.equals(":edit")) {
                            addMapping("GET", urlPrefix + "/edit"); // edit

                        } else if (only.equals(":update")) {
                            addMapping("PUT", urlPrefix);           // update

                        } else if (only.equals(":destroy")) {
                            addMapping("DELETE", urlPrefix);        // destroy

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
