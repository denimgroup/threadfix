package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.exception.ScanFileUnavailableException;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Created by mhatzenbuehler on 8/4/2014.
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.CLANG_DB_NAME,
        format = ScanFormat.ZIP
)
public class ClangChannelImporter extends AbstractChannelImporter {
    public ClangChannelImporter() {
        super(ScannerType.CLANG);
    }

    private static final String BUGTAIL = " -->";
    private static final String BUGDESC = "<!-- BUGDESC ";
    private static final String BUGTYPE = "<!-- BUGTYPE ";
    private static final String BUGCATEGORY = "<!-- BUGCATEGORY ";
    private static final String BUGPATH = "<!-- BUGFILE ";
    private static final String BUGLINE = "<!-- BUGLINE ";
    private static final String BUGCOLUMN = "<!-- BUGCOLUMN ";

    private static final String BUGFILE_START = "<tr><td class=\"rowname\">File:</td><td>";
    private static final String BUGFILE_END = "</td></tr>";

    private static final String REGEX_LINE_SOURCE = "<tr><td class=\"num\" id=\"LN[0-9]+\">[0-9]+</td><td class=\"line\">.*";
    private static final String REGEX_LINE_COMMENT = "<tr><td class=\"num\"></td><td class=\"line\"><div id=\"(End)*Path\\d*\" class=\"msg.*";
    private static final String REGEX_REPORT_FILE = ".*/report-[0-9a-f]{6}.html";

    @Override
    @Transactional
    public Scan parseInput() {
	    zipFile = unpackZipStream();

	    Scan scan = new Scan();

	    scan.setImportTime( getImportTime() );

        Map<String, InputStream> reports = getReportFiles();
        List<Finding> findings = new ArrayList<>(reports.size());

	    for (Map.Entry<String, InputStream> entry : reports.entrySet()) {
		    findings.add(parseInputStream(entry.getKey(), entry.getValue()));
	    }

        scan.setFindings(findings);

	    deleteZipFile();

	    return scan;
    }

	private Finding parseInputStream(String reportFileName, InputStream in) {

        List<DataFlowElement> dataFlowElements = new ArrayList<>();
        Map<FindingKey, String> findingKeyStringMap = new HashMap<>();

        String bugDesc = null;
        String bugType = null;
        String bugCategory = null;
        String bugPath = null;
        String bugFile = null;
        String bugLine = null;
        String bugColumn = null;

        String line, nonHtmlLine;
        String previousSourceLine = "";
        String previousLineNumber = "";

        boolean foundLastError = false;
        int dataFlowSeq = 0;

        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        try {
            line = reader.readLine();
            while (line != null && !foundLastError) {
                if (line.startsWith(BUGDESC) && line.endsWith(BUGTAIL))
                    bugDesc = StringUtils.substringBetween(line, BUGDESC, BUGTAIL);
                else if (line.startsWith(BUGTYPE) && line.endsWith(BUGTAIL))
                    bugType = StringUtils.substringBetween(line, BUGTYPE, BUGTAIL);
                else if (line.startsWith(BUGCATEGORY) && line.endsWith(BUGTAIL))
                    bugCategory = StringUtils.substringBetween(line, BUGCATEGORY, BUGTAIL);
                else if (line.startsWith(BUGPATH) && line.endsWith(BUGTAIL))
                    bugPath = StringUtils.substringBetween(line, BUGPATH, BUGTAIL);
                else if (line.startsWith(BUGLINE) && line.endsWith(BUGTAIL))
                    bugLine = StringUtils.substringBetween(line, BUGLINE, BUGTAIL);
                else if (line.startsWith(BUGCOLUMN) && line.endsWith(BUGTAIL))
                    bugColumn = StringUtils.substringBetween(line, BUGCOLUMN, BUGTAIL);
                else if (line.startsWith(BUGFILE_START) && line.endsWith(BUGFILE_END))
                    bugFile = StringUtils.substringBetween(line, BUGFILE_START, BUGFILE_END);

                if (line.matches(REGEX_LINE_SOURCE)) {
	                nonHtmlLine = line.replaceAll("<span class='expansion'>([^<]*)</span>", "");
                    nonHtmlLine = nonHtmlLine.replaceAll("<[^>]*>", "");                               // strip html
                    previousLineNumber = StringUtils.substringBetween(line, "id=\"LN", "\">");
                    previousSourceLine = nonHtmlLine.replaceFirst(previousLineNumber, "");
                } else if (line.matches(REGEX_LINE_COMMENT)) {
	                DataFlowElement element = new DataFlowElement();
                    element.setLineText(previousSourceLine);
                    element.setSourceFileName(bugFile);
                    if (line.contains("id=\"EndPath\"")) {
                        element.setLineNumber(Integer.parseInt(bugLine));
                        element.setColumnNumber(Integer.parseInt(bugColumn));
                        foundLastError = true;
                    } else {
                        element.setLineNumber(Integer.parseInt(previousLineNumber));
                    }
	                String prevElemLineText = null;
	                if (dataFlowSeq > 0) {
		                prevElemLineText = dataFlowElements.get(dataFlowSeq -1).getLineText();
	                }
					if (prevElemLineText != null && element.getLineText().equals(prevElemLineText)) {
						// concurrent line comments, overwrite last element
						element.setSequence(dataFlowSeq);
						dataFlowElements.set(dataFlowSeq-1, element);
					} else {
						element.setSequence(++dataFlowSeq);
						dataFlowElements.add(element);
					}
                }
                line = reader.readLine();
            }
	        reader.close();
        } catch (IOException e) {
            log.error("IOException thrown when reading file " + reportFileName, e);
        }


		String vulnCode = bugCategory.concat(":").concat(bugType);
        findingKeyStringMap.put(FindingKey.VULN_CODE, vulnCode);
        findingKeyStringMap.put(FindingKey.DETAIL, bugDesc);
        findingKeyStringMap.put(FindingKey.PATH, bugFile);
		findingKeyStringMap.put(FindingKey.SEVERITY_CODE, "Medium");

        Finding finding = super.constructFinding(findingKeyStringMap);
        if (finding == null) {
	        throw new IllegalStateException("XML was invalid or we didn't parse out enough information");
        }
        finding.setIsStatic(true);
        finding.setDataFlowElements(dataFlowElements);
		finding.setSourceFileLocation(bugPath);
		finding.setNativeId(getNativeIdFromReport(reportFileName));

        return finding;
    }

	private String getNativeIdFromReport(String input) {
		String id;
		id = StringUtils.substringBetween(input,"report-",".html");
		if (id == null)
			id = StringUtils.substringAfterLast(input,"/");
		if (id == null)
			id = input;
		if (id.length() > 50)
			id = id.substring(id.length() - 50);
		return id;
	}

    private Map<String, InputStream> getReportFiles() {
        if (zipFile.entries() == null) {
            throw new ScanFileUnavailableException("No zip entries were found in the zip file.");
        }

        Map<String, InputStream> m = new HashMap<>();
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (entry.getName().matches(REGEX_REPORT_FILE)) {
                try {
                    m.put(entry.getName(), zipFile.getInputStream(entry));
                } catch (IOException e) {
                    log.error("IOException thrown when reading entries from zip file.", e);
                }
            }
        }
        return m;
    }

    private Calendar getImportTime() {
	    InputStream indexHtml = getFileFromZip("index.html");
	    if (indexHtml == null)
		    return null;
	    try {
		    String s = IOUtils.toString(indexHtml);
		    String sDate = StringUtils.substringBetween(s,"<tr><th>Date:</th><td>","</td></tr>");
		    //  Mon Aug  4 13:18:00 2014
		    return DateUtils.getCalendarFromString("EEE MMM dd HH:mm:ss yyyy", sDate);
	    } catch (IOException e) {
		    log.error("IOException reading inputstream index.html in getTestDate(indexHtml)",e);
		    return null;
	    }
    }

	@Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
	    try {
		    zipFile = unpackZipStream();

		    if (zipFile == null)
			    return new ScanCheckResultBean(ScanImportStatus.NULL_INPUT_ERROR);

		    InputStream indexHtml = getFileFromZip("index.html");
		    if (indexHtml == null)
			    return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);

		    Integer findingCount = getFindingCount(zipFile);
		    if (findingCount == null)
			    return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);
		    else if (findingCount < 1)
			    return new ScanCheckResultBean(ScanImportStatus.EMPTY_SCAN_ERROR);

		    testDate = getTestDate(indexHtml);

		    ScanImportStatus scanImportStatus = checkTestDate();

		    return new ScanCheckResultBean(scanImportStatus, testDate);

	    } finally {
		    deleteZipFile();
	    }
	}

	private Integer getFindingCount(ZipFile zipFile) {
		if (zipFile.entries() == null) {
			return null;
		}
		int i = 0;
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			ZipEntry entry = entries.nextElement();
			if (entry.getName().matches(REGEX_REPORT_FILE)) {
				i++;
			}
		}
		return i;
	}

	private Calendar getTestDate(InputStream indexHtml) {
		try {
			String s = IOUtils.toString(indexHtml);
			String sDate = StringUtils.substringBetween(s,"<tr><th>Date:</th><td>","</td></tr>");
			//  Mon Aug  4 13:18:00 2014
			return DateUtils.getCalendarFromString("EEE MMM dd HH:mm:ss yyyy", sDate);
		} catch (IOException e) {
			log.error("IOException reading inputstream index.html in getTestDate(indexHtml)",e);
			return null;
		}
	}

}
