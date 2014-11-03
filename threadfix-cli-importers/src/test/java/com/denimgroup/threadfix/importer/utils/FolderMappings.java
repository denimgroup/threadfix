package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.ScanLocationManager;

import java.util.*;

/**
 * Created by mac on 2/11/14.
 */
public class FolderMappings {

    static Map<ScannerType, Collection<String>> items = new HashMap<>();

    static {
        addToMap(ScannerType.ACUNETIX_WVS, "Dynamic/Acunetix");
        addToMap(ScannerType.APPSCAN_DYNAMIC, "Dynamic/AppScan");
        addToMap(ScannerType.APPSCAN_ENTERPRISE, "Dynamic/AppScanEnterprise");
        addToMap(ScannerType.ARACHNI, "Dynamic/Arachni");
        addToMap(ScannerType.BURPSUITE, "Dynamic/Burp");
        addToMap(ScannerType.CENZIC_HAILSTORM, "Dynamic/CenzicHailstorm");
        addToMap(ScannerType.NESSUS, "Dynamic/Nessus");
        addToMap(ScannerType.NETSPARKER, "Dynamic/NetSparker");
        addToMap(ScannerType.NTO_SPIDER, "Dynamic/NTOSpider");
        addToMap(ScannerType.SKIPFISH, "Dynamic/Skipfish");
        addToMap(ScannerType.W3AF, "Dynamic/w3af");
        addToMap(ScannerType.WEBINSPECT, "Dynamic/WebInspect");
        addToMap(ScannerType.ZAPROXY, "Dynamic/ZAP");
        addToMap(ScannerType.BRAKEMAN, "Static/Brakeman");
        addToMap(ScannerType.CAT_NET, "Static/CAT.NET");
        addToMap(ScannerType.CHECKMARX, "Static/Checkmarx");
        addToMap(ScannerType.FINDBUGS, "Static/FindBugs");
        addToMap(ScannerType.FORTIFY, "Static/Fortify");
        addToMap(ScannerType.DEPENDENCY_CHECK, "Static/DependencyCheck");
        addToMap(ScannerType.PMD, "Static/PMD");
        addToMap(ScannerType.CLANG, "Static/Clang");
	    addToMap(ScannerType.CPPCHECK, "Static/Cppcheck");
        addToMap(ScannerType.SSVL, "Manual/SSVL");
    }

    private static void addToMap(ScannerType type, String fileKey) {
        if (!items.containsKey(type)) {
            items.put(type, new HashSet<String>());
        }

        items.get(type).addAll(ScanLocationManager.getFilesInDirectory(fileKey));
    }

    public static boolean containsKey(ScannerType scannerType) {
        return items.containsKey(scannerType);
    }

    public static Collection<String> getValue(ScannerType key) {
        return items.get(key);
    }

    public static Iterable<Map.Entry<ScannerType, Collection<String>>> getEntries() {
        return items.entrySet();
    }

    public static Iterable<ScannerType> getKeys() {
        return items.keySet();
    }
}
