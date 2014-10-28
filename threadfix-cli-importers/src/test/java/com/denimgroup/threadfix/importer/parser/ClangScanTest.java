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
