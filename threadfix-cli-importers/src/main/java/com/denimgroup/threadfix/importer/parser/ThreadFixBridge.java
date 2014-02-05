package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;

import java.io.File;

public interface ThreadFixBridge  {

    public ScannerType getType(File file);

    public ScanCheckResultBean testScan(ScannerType type, File inputFile);

    public Scan getScan(ScannerType type, File inputFile);

}
