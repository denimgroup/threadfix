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
package com.denimgroup.threadfix.importer.loader;

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.annotations.StartingTagSet;
import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import com.denimgroup.threadfix.importer.util.ZipFileUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.io.*;
import java.nio.file.Files;
import java.util.AbstractMap.SimpleEntry;
import java.util.*;
import java.util.Map.Entry;
import java.util.zip.ZipFile;

import static com.denimgroup.threadfix.CloseableUtils.closeQuietly;
import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

@Service
public class ScanTypeCalculationServiceImpl implements ScanTypeCalculationService {
	
	private final SanitizedLogger log = new SanitizedLogger(ScanTypeCalculationService.class);

    public static final String TEMP_FILE_NAME = "tempFile";

    private boolean initialized = false;

	private static final List<String> REMOTE_PROVIDERS = Arrays.asList(
			"QualysGuard WAS",
			"Veracode",
			"Contrast");

    @Autowired
	private ApplicationDao applicationDao;
    @Autowired
	private ApplicationChannelDao applicationChannelDao;
    @Autowired
	private ChannelTypeDao channelTypeDao;
    @Autowired
    private DefaultConfigService defaultConfigService;

	private String getScannerType(MultipartFile file) {

        DefaultConfiguration defaultConfig = defaultConfigService.loadCurrentConfiguration();
        String fileUploadLocation = defaultConfig.getFileUploadLocation();
        String fullFilePath = TEMP_FILE_NAME;

        if(defaultConfig.fileUploadLocationExists()) {
            File directory = new File(fileUploadLocation);

            if (directory.exists()){
                File fileUploaded = new File(fileUploadLocation + File.separator + TEMP_FILE_NAME);
                fullFilePath = fileUploaded.getPath();
            } else {
                throw new RestIOException("Directory at path:  " + fileUploadLocation + " does not exist.", -1);
            }
        }

		saveFile(fullFilePath,file);

        String returnValue = getScannerType(file.getOriginalFilename(), fullFilePath);

        deleteFile(fullFilePath);

		if (REMOTE_PROVIDERS.contains(returnValue)) {
			throw new RestIOException("Import " + returnValue + " scans using the Remote Provider functionality.", -1);
		}

        return returnValue;
	}

    // package access is for testing
    // the two arguments are needed to reconcile MultipartFile / File difference
    String getScannerType(String originalName, String fileName) {

        if (!initialized) {
            initializeMappingsFromAnnotations();
        }

        String returnString = null;

        if (ScanUtils.isZip(fileName)) {
            returnString = figureOutZip(fileName);
        } else if (originalName.endsWith("json")){
			returnString = figureOutJson(fileName);
        } else if (originalName.endsWith(".html")) {
            //probably clang
            returnString = ScannerType.CLANG.getFullName();
        } else {
            returnString = figureOutXml(fileName);
        }

        return returnString;
    }

    @Override
    public ScannerType getScannerType(File inputFile) {
        ScannerType type = null;

        if (inputFile.exists() && !inputFile.isDirectory()) {
            String scannerName = getScannerType(inputFile.getAbsolutePath(), inputFile.getAbsolutePath());

			if (scannerName != null) {
				type = ScannerType.getScannerType(scannerName);
			}
        }

        return type;
    }

    private static final Set<Entry<String, String[]>> map = set();
	private static final Set<Entry<String, ScanImporter>> jsonMap = set();
	private static void addToJSONMap(String name, ScanImporter scanImporter) {
		jsonMap.add(new SimpleEntry<String, ScanImporter>(name, scanImporter));
	}
    private static void addToMap(String name, String... tags) {
        map.add(new SimpleEntry<String, String[]>(name, tags));
    }

    private void initializeMappingsFromAnnotations() {

        Map<Class<?>, ScanImporter> typeMap =
                AnnotationLoader.getMap(
                        ScanImporter.class,
                        "com.denimgroup.threadfix.importer.impl.upload");

        for (Entry<Class<?>, ScanImporter> entry : typeMap.entrySet()) {
            ScanImporter annotation = entry.getValue();

			if (annotation.format() == ScanFormat.JSON) {
				boolean addedEntry = false;

				if (annotation.jsonStructure() != ScanImporter.JSONStructure.NONE) {
					addToJSONMap(annotation.scannerName(), annotation);
					addedEntry = true;
				}

				assert addedEntry : "Failed to add an JSON path for scanner " + annotation.scannerName();
			}

            if (annotation.format() == ScanFormat.XML) {
                boolean addedEntry = false;

                if (annotation.startingXMLTags().length != 0) {
                    addToMap(annotation.scannerName(), annotation.startingXMLTags());
                    addedEntry = true;

                } else if (annotation.startingXMLTagSets().length != 0) {
                    for (StartingTagSet startingTagSet : annotation.startingXMLTagSets()) {
                        if (startingTagSet.value().length != 0) {
                            addToMap(annotation.scannerName(), startingTagSet.value());
                            addedEntry = true;
                        }
                    }
                }

                assert addedEntry : "Failed to add an XML entry for scanner " + annotation.scannerName();
            }
        }

        initialized = true;
    }

    // We currently only have zip files for skipfish and fortify
	// if we support a few more it would be worth a more modular style
	private String figureOutZip(String fileName) {

		String result = null;
		ZipFile zipFile = null;
		try {
			zipFile = new ZipFile(DiskUtils.getScratchFile(fileName));

			if (zipFile.getEntry("audit.fvdl") != null) {
				result = ScannerType.FORTIFY.getDbName();
			} else if (ZipFileUtils.getZipEntry("issue_index.js", zipFile) != null){
				result = ScannerType.SKIPFISH.getFullName();
			} else if (zipFile.getEntry("index.html") != null
                    && zipFile.getEntry("scanview.css") != null) {
                result = ScannerType.CLANG.getFullName();
            }
		} catch (FileNotFoundException e) {
			log.warn("Unable to find zip file.", e);
		} catch (IOException e) {
			log.warn("Exception encountered while trying to identify zip file.", e);
		} finally {
			closeQuietly(zipFile);
		}
		
		return result;
	}

	private String figureOutXml(String fileName) {
		try {
			TagCollector collector = new TagCollector();
			
			InputStream stream = new FileInputStream(DiskUtils.getScratchFile(fileName));
			
			ScanUtils.readSAXInput(collector, "Done.", stream);
			
			return getType(collector.tags);
		} catch (IOException e) {
			log.error("Encountered IOException. Rethrowing.");
            throw new RestIOException(e, "Unable to determine scan type.");
		} catch (RestIOException e) {
			log.error("Encountered IOException. Rethrowing.");
            throw new RestIOException(e, "Unable to determine scan type.");
		}
	}

	private String figureOutJson(String filename) {
		String result = null;
		JSONObject jsonObject = null;
		JSONArray jsonArray = null;

		try {
			String jsonInput = IOUtils.toString(new FileInputStream(filename));
			if ('[' == (jsonInput.trim().charAt(0))) {
				jsonArray = new JSONArray(jsonInput);
			} else if ('{' == (jsonInput.trim().charAt(0))) {
				jsonObject = new JSONObject(jsonInput);
			}
		} catch (JSONException e) {
			log.debug("Error attempting to determine first element type of JSON input.", e);
		} catch (IOException e) {
			log.debug("Error attempting to determine first element type of JSON input.", e);
		}

		for (Entry<String, ScanImporter> entry : jsonMap) {
			ScanImporter scanImporter = entry.getValue();

			if (jsonObject != null && scanImporter.jsonStructure() == ScanImporter.JSONStructure.OBJECT) {
				if (matchProperties(scanImporter.jsonProperties(), jsonObject)) {
					result = entry.getKey();
				}
			} else if (jsonArray != null && scanImporter.jsonStructure() == ScanImporter.JSONStructure.LIST_OF_OBJECTS) {
				try {
					jsonObject = jsonArray.getJSONObject(0);
				} catch (JSONException e) {
					log.debug("Unable to get first object from JSON array. Check file format.", e);
				}

				if (matchProperties(scanImporter.jsonProperties(), jsonObject)) {
					result =  entry.getKey();
				}
			}
		}

		return result;
	}

	private boolean matchProperties(String[] properties ,JSONObject jsonObject) {
		for (String property : properties) {
			if (!jsonObject.has(property)) {
				return false;
			}
		}
		return true;
	}


	private String getType(List<String> scanTags) {
		
		for (Entry<String, String[]> entry : map) {
			if (matches(scanTags, entry.getValue())) {
				return entry.getKey();
			}
		}
		
		return null;
	}
	
	private boolean matches(List<String> scanTags, String[] channelTags) {
		
		if (scanTags.size() >= channelTags.length) {
			for (int i = 0; i < channelTags.length; i++) {
				if (!scanTags.get(i).equals(channelTags[i])) {
					return false;
				}
				
				if (i == channelTags.length - 1) {
					return true;
				}
			}
		}
		
		return false;
	}
	
	private void deleteFile(String fileName) {
		File file = new File(fileName);
		if (file.exists() && !file.delete()) {
			log.warn("Something went wrong trying to delete the file.");
			
			file.deleteOnExit();
		}
	}
	
	public class TagCollector extends DefaultHandler {
		public List<String> tags = list();
		private int index = 0;
		
	    @Override
		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
    		if (index++ > 10) {
	    		throw new SAXException("Done.");
	    	}
    		
    		tags.add(qName);
	    }
	}
	
	@Override
	public Integer calculateScanType(int appId, MultipartFile file, String channelIdString) {
		ChannelType type = null;
		
		Integer channelId = null;
		if (channelIdString != null && !channelIdString.trim().isEmpty()) {
			channelId = IntegerUtils.getIntegerOrNull(channelIdString);
		}
		
		if (channelId == null || channelId == -1) {
			String typeString = getScannerType(file);
			if (typeString != null && !typeString.trim().isEmpty()) {
				type = channelTypeDao.retrieveByName(typeString);
			} else {
				return null;
			}
		} else {
			type = channelTypeDao.retrieveById(channelId);
		}
		
		if (type != null) {
			ApplicationChannel channel = applicationChannelDao.retrieveByAppIdAndChannelId(
					appId, type.getId());
			if (channel != null) {
				return channel.getId();
			} else {
				Application application = applicationDao.retrieveById(appId);
				channel = new ApplicationChannel();
				channel.setChannelType(type);
				application.getChannelList().add(channel);
				channel.setApplication(application);
				channel.setScanList(new ArrayList<Scan>());
				
				channel.setApplication(application);
				if (!isDuplicate(channel)) {
					applicationChannelDao.saveOrUpdate(channel);
					return channel.getId();
				}
			}
		}
		return null;
	}
	
	public boolean isDuplicate(ApplicationChannel applicationChannel) {
		if (applicationChannel.getApplication() == null
				|| applicationChannel.getChannelType().getId() == null) {
			return true;
		}
		
		ApplicationChannel dbAppChannel = applicationChannelDao.retrieveByAppIdAndChannelId(
				applicationChannel.getApplication().getId(), applicationChannel.getChannelType()
						.getId());
		return dbAppChannel != null && !applicationChannel.getId().equals(dbAppChannel.getId());
	}
	
	@Override
	public String saveFile(Integer channelId, MultipartFile file) {
		if (channelId == null || file == null) {
			log.warn("The scan upload file failed to save, it had null input.");
			return null;
		}

        DefaultConfiguration defaultConfig = defaultConfigService.loadCurrentConfiguration();
        String fileUploadLocation = defaultConfig.getFileUploadLocation();

		checkDiskSpace(file);

		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);

		if (applicationChannel == null) {
			log.warn("Unable to retrieve Application Channel - scan save failed.");
			return null;
		}

		String inputFileName = applicationChannel.getNextFileHandle();

        if(defaultConfig.fileUploadLocationExists()) {
            File fileUploaded = new File(fileUploadLocation + File.separator + inputFileName);
            inputFileName = fileUploaded.getPath();
        }

		applicationChannel.setScanCounter(applicationChannel.getScanCounter() + 1);

		applicationChannelDao.saveOrUpdate(applicationChannel);

		return saveFile(inputFileName, file);
	}

	private void checkDiskSpace(MultipartFile file) {
		long usableSpace = DiskUtils.getAvailableDiskSpace();

		long size = file.getSize();

		String sizeMessage = "need " + size + " bytes to write file, " + usableSpace + " available.";

		if (size > usableSpace) {
			log.error("Not enough space to write temporary scan file: " + sizeMessage);
			throw new RestIOException("Not enough disk space to store temporary scan file.", 200);
		} else {
			log.debug("Should have enough room: " + sizeMessage);
		}
	}

	private String saveFile(String inputFileName, MultipartFile file) {
        String returnValue = null;

		InputStream stream = null;
		FileOutputStream out = null;
		try {

			stream = file.getInputStream();
            File diskFile = DiskUtils.getScratchFile(inputFileName);
            try {
				out = new FileOutputStream(diskFile);
                byte[] buf = new byte[1024];
                int len;

                while ((len = stream.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }

                returnValue = inputFileName;

            } catch (IOException e) {
                log.warn("Writing the file stream to disk encountered an IOException.", e);
            }
		} catch (IOException e) {
            log.warn("Failed to retrieve an InputStream from the file upload.", e);
		} finally {
			closeQuietly(stream);
			closeQuietly(out);
		}

		return returnValue;
	}
}
