package com.denimgroup.threadfix.scanagent.util;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;

public class ConfigurationUtils {
	private static Logger log = Logger.getLogger(ConfigurationUtils.class);
//	public static final String WORKING_DIR = System.getProperty("user.dir") + "/";
////	public static final String WORKING_FILE_NAME = "configTemp.properties";
//	public static final String WORKING_FILE_NAME = "scanagent.properties";
	
	public static void saveUrlConfig(String url, Configuration config) {
		log.info("Start saving url");
		writeToFile(new String[]{"scanagent.threadFixServerUrl"}, new String[]{url}, config);
		log.info("Ended saving url");
	}
	
	public static void saveKeyConfig(String key, Configuration config) {
		log.info("Start saving key");
		writeToFile(new String[]{"scanagent.threadFixApiKey"}, new String[]{key}, config);
		log.info("Ended saving key");
	}
	
	public static void saveWorkDirectory(String workdir, Configuration config) {
		log.info("Start saving working directory");
		writeToFile(new String[]{"scanagent.baseWorkDir"}, new String[]{workdir}, config);
		log.info("Ended saving working directory");
	}
	
	public static void saveScannerType(Scanner scan, Configuration config) {
		log.info("Start saving scanner type");
		String[] names = new String[5];
		String[] values = new String[5];
		String name = "";
		for (ScannerType type : ScannerType.values()) {
			if (scan.getName().equalsIgnoreCase(type.getShortName()) || scan.getName().equalsIgnoreCase(type.getFullName())) {
				name = type.getShortName();
				names[0] = type.getShortName() + ".scanName";
				values[0] = type.getFullName();
				break;
			}
		}
		names[1] = name + ".scanVersion";
		names[2] = name + ".scanExecutablePath";
		names[3] = name + ".scanHost";
		names[4] = name + ".scanPort";
		values[1] = scan.getVersion();
		values[2] = scan.getHomeDir();
		values[3] = scan.getHost();
		values[4] = String.valueOf(scan.getPort());
		writeToFile(names, values, config);
		log.info("Ended saving scanner type");
	}
	
	public static List<Scanner> readAllScanner(Configuration config) {
		log.info("Start reading all scanner type");
		List<Scanner> scanners = new ArrayList<Scanner>();
		Scanner scan = new Scanner();
		try {
			for (ScannerType type : ScannerType.values()) {
				String scanName = config.getString(type.getShortName() + ".scanName");
				if (scanName != null && !scanName.isEmpty()) {
					scan.setName(scanName);
					scan.setVersion(config.getString(type.getShortName() + ".scanVersion"));
					scan.setHomeDir(config.getString(type.getShortName() + ".scanExecutablePath"));
					scan.setHost(config.getString(type.getShortName() + ".scanHost"));
					scan.setPort(Integer.valueOf(config.getString(type.getShortName() + ".scanPort")));
					scanners.add(scan);
				}
			}			
		} catch (Exception e) {
			log.error("Problems reading configuration: " + e.getMessage(), e);
			return scanners;
		} 
		
		log.info("Number of scanners available: " + scanners.size());
		return scanners;
	}
	
	private static void writeToFile(String[] names, String[] values, Configuration config) {
		
		if (names.length != values.length) return;
		
		for (int i=0;i<names.length;i++) {
			String name = names[i];
			if (config.getString(name,"").isEmpty())
				config.addProperty(name, values[i]);
			else config.setProperty(name, values[i]);
		}
		
	
	}
	
	public static boolean isDirectory(String path) {
		File file = new File(path);
		if (!file.exists() || !file.isDirectory())
			return false;
		return true;
	}

	public static boolean checkHomeParam(String[] args) {

		String osName = System.getProperty("os.name");
		
		if (args[0].equalsIgnoreCase(ScannerType.ZAPROXY.getShortName()) || args[0].equalsIgnoreCase(ScannerType.ZAPROXY.getFullName())) {
			if (osName.contains("Windows")) {
				File zapExeFile = new File(args[2] + "/zap.bat");
				if (!zapExeFile.exists() || !zapExeFile.isFile())
					return false;
			} else {
				File zapExeFile = new File(args[2] + "/zap.sh");
				if (!zapExeFile.exists() || !zapExeFile.isFile())
					return false;
			}
		}
		return true;
	}

}
