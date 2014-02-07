package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Component;

import java.io.File;

@Component
public class CommandLineMain {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(CommandLineMain.class);

    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();

        CommandLineMain main = SpringConfiguration.getContext().getBean(CommandLineMain.class);

        LOGGER.info("Initialization finished in " + (System.currentTimeMillis() - startTime) + " ms");

        main.mainWithSpring(args);
    }

    public void mainWithSpring(String[] args) {
        if (check(args)) {
            long startTime = System.currentTimeMillis();

            String output = SpringConfiguration.getContext().getBean(ScanParser.class).readFile(args[0]);

            LOGGER.info("Scan parsing finished in " + (System.currentTimeMillis() - startTime) + " ms");
            System.out.println(output);
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
