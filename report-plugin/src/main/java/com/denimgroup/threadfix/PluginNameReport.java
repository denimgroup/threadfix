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

package com.denimgroup.threadfix;

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.annotations.ReportPlugin;

@ReportPlugin(
        /*
         * Relative file path to the javascript file that contains any and all
         * js the report plugin depends on
         * 
         * Rename file based on name/description of plugin
         */
        jsRelFilePath = "/scripts/report-plugin.js",
        
        /*
         * Relative file path to the jsp file that contains any and all 
         * html the report plugin needs for rendering
         * 
         * Rename file based on name/description of plugin
         */
        jspRelFilePath = "/WEB-INF/views/applications/widgets/reportPlugin.jsp",
        
        /*
         * Serves as the unique short name of the report plugin
         * 
         * Rename property based on name/description of plugin
         */
        shortName = "pluginName",
        
        /*
         * Name that is displayed in System Settings in reference to the report plugin
         * 
         * Rename based on name/description of plugin
         */
        displayName = "Plugin Name",

        /*
         * Notes all the places where this report plugin can show up
         *
         * Locations are noted in the ReportLocation enum (ex. ReportLocation.TEAM)
         */
        locations = { ReportLocation.APPLICATION, ReportLocation.DASHBOARD, ReportLocation.TEAM })
/*
 * Empty class to hold report plugin metadata
 * 
 * Rename class based on name/description of plugin
 */
public class PluginNameReport {


}
