package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanImportStatus;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.stereotype.Component;

import java.io.File;

@Component
public class CommandLineMain {

    private static AnnotationConfigApplicationContext context = null;


    public static AnnotationConfigApplicationContext getContext() {
        if (context == null) {
            context = new AnnotationConfigApplicationContext();
            context.register(SpringConfiguration.class);
            context.refresh();
        }
        return context;
    }

    // Bootstrap Spring components
    public static void main(String[] args) {
        getContext().getBean(CommandLineMain.class).springyMain(args);
    }

    @Autowired
    ThreadFixBridge bridge;

    @Autowired
    ChannelTypeDao channelTypeDao;

    public void springyMain(String[] args) {
        if (check(args)) {
            File scanFile = new File(args[0]);

            ScannerType scannerType = bridge.getType(scanFile);

            if (scannerType == null) {
                System.out.println("Unable to determine the scan type of the file.");
            } else {
                ScanCheckResultBean resultBean = bridge.testScan(scannerType, scanFile);

                if (resultBean.getScanCheckResult() == ScanImportStatus.SUCCESSFUL_SCAN) {
                    Scan result = bridge.getScan(scannerType, scanFile);

                    for (Finding finding : result.getFindings()) {
                        System.out.println("Finding: " + finding);
                    }

                } else {
                    System.out.println("Scan check failed and returned the following status: " + resultBean.getScanCheckResult());
                }
            }
        }
    }

    private static boolean check(String[] args) {
        if (args.length != 1) {
            System.out.println("This program accepts one argument, the scan file to be scanned.");
            return false;
        }

        File scanFile = new File(args[0]);

        if (!scanFile.exists()) {
            System.out.println("The file must exist.");
            return false;
        }

        if (scanFile.isDirectory()) {
            System.out.println("The file must not be a directory.");
            return false;
        }

        return true;
    }


}
