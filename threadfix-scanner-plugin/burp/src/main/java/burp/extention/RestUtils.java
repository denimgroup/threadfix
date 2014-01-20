package burp.extention;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;

public class RestUtils {

    private RestUtils(){}

    public static int uploadScan(File file) {
        if (getKey() == null || getUrl() == null) {
            return -2;
        } else {
            return httpPostFile(getUrl() + "/applications/" + getApplicationId() + "/upload",
                file);
        }
    }

    private static String getKey() {
        return ThreadFixPropertiesManager.getKey();
    }

    private static String getUrl() {
        return ThreadFixPropertiesManager.getUrl();
    }

    private static String getApplicationId() {
        return ThreadFixPropertiesManager.getAppId();
    }

    public static String getApplications() {
        return httpGet(getUrl() + "/code/applications/?apiKey=" + getKey());
    }

    public static String getEndpoints() {
        return httpGet(getUrl() + "/code/applications/" + getApplicationId() + "/endpoints?apiKey=" + getKey());
    }

    public static String httpGet(String urlStr) {
        StringBuffer response = new StringBuffer();
        try {
            URL url = new URL(urlStr);
            HttpURLConnection urlconn = (HttpURLConnection) url.openConnection();
            urlconn.setRequestMethod("GET");
            urlconn.setRequestProperty("Accept", "application/json");
            urlconn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");

            urlconn.getResponseCode();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(urlconn.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append("\n" + inputLine);
            }
            in.close();
            urlconn.disconnect();

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return "error";
        }
        return response.toString();
    }

    private static int httpPostFile(String request, File file) {

        int status = -1;
        String charset = "UTF-8";
        try {
            MultipartUtility multipart = new MultipartUtility(request, charset);
            multipart.addHeaderField("Accept", "application/json");
            multipart.addFormField("apiKey", getKey());
            multipart.addFilePart("file", file);
            status = multipart.finish();
        } catch (IOException ex) {
        }

        return status;
    }


}
