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

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

/**
 * Created by mhatzenbuehler on 8/4/2014.
 */
public class ClangScanTest {
    //cwe name, severity, path, parameter
    private final static String[][] clangResults = new String [][] {
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "PreferencesViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "HistoryViewController.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "ASI/ASIDownloadCache.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "TipViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "BuyViewController.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "TipViewController.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "BuyViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "HistoryViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "TipViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "BuyViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "HistoryViewController.m", ""},
		    {"Divide By Zero", "Medium", "ASI/ASIHTTPRequest.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "StockDatabase.m", ""},
		    {"Improper Following of Specification by Caller", "Medium", "ASI/ASIAuthenticationDialog.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "TipViewController.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "BuyViewController.m", ""},
		    {"Assignment to Variable without Use ('Unused Variable')", "Medium", "BuyViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "TipViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "TipViewController.m", ""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')", "Medium", "HistoryViewController.m", ""}
    };

	@Test
	public void clangScanTest() {
		ScanComparisonUtils.compare(clangResults, ScanLocationManager.getRoot() +
				"Static/Clang/Clang-Archive.zip");
	}
}
