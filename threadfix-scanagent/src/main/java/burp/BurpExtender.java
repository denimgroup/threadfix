package burp;

import burp.extension.ScanQueueMap;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 1/8/14
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{

    public static final String TARGET_URL = "target_url";
    public static final String WORKING_DIRECTORY = "working_directory";
    public static final String STATE_FILE = "state_file";
    public static final String EXPORT_RESULT_FILE_NAME = "burp_scan_result.xml";
    public static final String STATE_FILE_NAME = "application.state";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JRootPane rootPane;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private String separator = File.separator;
    private String target = "";
    private String workDir = "";
    private String stateFileName = "";
    private ScanQueueMap map = new ScanQueueMap();

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("ScanAgent plugin");

        String[] argsList = callbacks.getCommandLineArguments();
        if (argsList.length%2 != 0 || argsList.length == 0) {
            System.out.println("Invalid arguments. Stop Burp without doing anything.");
            stop();
            return;
        }

        String argName;
        for (int i=0;i<argsList.length/2;i++) {
            argName = argsList[i*2];
            switch (argName) {
                case TARGET_URL: target = argsList[i*2+1];
                    break;
                case WORKING_DIRECTORY: workDir = argsList[i*2+1];
                    break;
                case STATE_FILE: stateFileName = argsList[i*2+1];
                    break;
                default:
                    break;
            }
        }

        // Load state if there's any
        restoreState();
        // Active Scan and Report
        try {
            doActiveScanAndReport();
            exportReport();
        }     catch (MalformedURLException e) {
            System.out.println("The target Url is invalid.Exiting...");
            stop();
            return;
        }
        stop();
    }

    private void restoreState() {
        if (!stateFileName.isEmpty()) {
            System.out.println("About to restore State");
            File stateFile = new File(workDir+separator+stateFileName);
            if (stateFile.isFile()) {
                callbacks.restoreState(stateFile);
            }
        }
    }

    private void doActiveScanAndReport() throws MalformedURLException{

        if (target.isEmpty())
            return;

        if (stateFileName.isEmpty()) {
            URL targetUrl = new URL(target);
            callbacks.sendToSpider(targetUrl);
            System.out.println("Preparing for SiteMap");
            scanSiteMap(target);
            try {
                Thread.sleep(1000);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("About to start scanning");
        scanSiteMap(target);
    }

    private void scanSiteMap(String baseUrl){
        for (IHttpRequestResponse rr : callbacks.getSiteMap(null)) {
            try {
                URL url = new URL(baseUrl);
                URL urlProxy = callbacks.getHelpers().analyzeRequest(rr).getUrl();
                if (equalUrls(urlProxy, url)) {
//                    System.out.println("callbacks.isInScope("+urlProxy+") is "+callbacks.isInScope(urlProxy));
                    if (!callbacks.isInScope(urlProxy)) {
                        callbacks.includeInScope(urlProxy);
                    }
                    boolean useHttps = rr.getHttpService().getProtocol().equalsIgnoreCase("https");
                    System.out.println("About to scan: "+urlProxy);
                    IScanQueueItem isq = null;
                    isq = callbacks.doActiveScan(rr.getHttpService().getHost(), rr.getHttpService().getPort(), useHttps, rr.getRequest());
//                    System.out.println("Adding " + urlProxy.toExternalForm() + " to ScanQueueMap");
                    map.addItem(urlProxy.toExternalForm(), isq);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        map.waitForAllToComplete();
        map.clear();
    }
    private void exportReport() {
        System.out.println("Exporting scan result to " + workDir + separator + EXPORT_RESULT_FILE_NAME);
        File file = new File(workDir + separator + EXPORT_RESULT_FILE_NAME);
        IScanIssue[] issues = callbacks.getScanIssues(target);
        System.out.println("There are " + issues.length + " issues");
        callbacks.generateScanReport("XML", issues, file);
    }

    private boolean equalUrls(URL first, URL second) {
        if (!first.getHost().equals(second.getHost())) return false;
        if (first.getPort() != (second.getPort())) return false;
        if (!first.getProtocol().equals(second.getProtocol())) return false;
        if (!first.getPath().startsWith(second.getPath())) return false;
        return true;
    }

    private void stop() {
        this.callbacks.exitSuite(true);
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "ThreadFix";
    }

    @Override
    public Component getUiComponent()
    {
        return rootPane;
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // only process responses
        if (!messageIsRequest)
        {
            // create a new log entry with the message details
            synchronized(log)
            {
                int row = log.size();
                log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
        }
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 2;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Tool";
            case 1:
                return "URL";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // class to hold details of each log entry
    //

    private static class LogEntry
    {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url)
        {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
        }
    }

}
