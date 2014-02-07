package com.denimgroup.threadfix.importer.impl;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.testutils.ScanFileUtils;
import org.junit.Test;
import org.mockito.InjectMocks;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class ScanTypeCalculatorTests {

    @InjectMocks
    ScanTypeCalculationServiceImpl service = new ScanTypeCalculationServiceImpl();

    static Map<ScannerType, Collection<String>> items = new HashMap<>();

    static {
        addToMap(ScannerType.ACUNETIX_WVS, "Dynamic/Acunetix");
        addToMap(ScannerType.APPSCAN_DYNAMIC, "Dynamic/AppScan");
        addToMap(ScannerType.APPSCAN_ENTERPRISE, "Dynamic/AppScanEnterprise");
        addToMap(ScannerType.ARACHNI, "Dynamic/Arachni");
        addToMap(ScannerType.BURPSUITE, "Dynamic/Burp");
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
    }

    private static void addToMap(ScannerType type, String fileKey) {
        if (!items.containsKey(type)) {
            items.put(type, new HashSet<String>());
        }

        items.get(type).addAll(ScanFileUtils.getFilesInDirectory(fileKey));
    }

    @Test
    public void testFalseNegatives() {
        for (ScannerType type : ScannerType.values()) {
            if (items.containsKey(type)) {
                System.out.println(items.get(type).size() + " scan file(s) found for " + type);
            } else {
                System.out.println("No items found for " + type + ". You should think about fixing that.");
            }
        }

        for (Map.Entry<ScannerType, Collection<String>> entry : items.entrySet()) {
            for (String file : entry.getValue()) {
                String type = service.getScannerType(file, file);
                assertEquals("Failed for file " + file, entry.getKey().getFullName(), type);
            }
        }
    }

    @Test
    public void testFalsePositives() {
        for (ScannerType outerEntry : items.keySet()) {
            for (Map.Entry<ScannerType, Collection<String>> innerEntry : items.entrySet()) {
                if (innerEntry.getKey() != outerEntry) {
                    for (String file : innerEntry.getValue()) {
                        String type = service.getScannerType(file, file);
                        assertNotEquals(outerEntry + " falsely identified file " + file, outerEntry.getFullName(), type);
                    }
                }
            }
        }
    }


}
