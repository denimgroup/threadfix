package com.denimgroup.threadfix.webapp.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by stran on 4/3/14.
 */
public class MessageConstants {

    public static final String ERROR_MAXLENGTH = "errors.maxlength";
    public static final String ERROR_MINLENGTH = "errors.minlength";
    public static final String ERROR_RANGE = "errors.range";

    public static final String ERROR_INVALID = "errors.invalid";
    public static final String ERROR_BYTE = "errors.byte";
    public static final String ERROR_DATE = "errors.date";
    public static final String ERROR_DOUBLE = "errors.double";
    public static final String ERROR_FLOAT = "errors.float";
    public static final String ERROR_INTEGER = "errors.integer";
    public static final String ERROR_LONG = "errors.long";
    public static final String ERROR_SHORT = "errors.short";

    public static final String ERROR_URL = "errors.url";
    public static final String ERROR_REQUIRED = "errors.required";
    public static final String ERROR_CREDITCARD = "errors.creditcard";
    public static final String ERROR_EMAIL = "errors.email";
    public static final String ERROR_PHONE = "errors.phone";
    public static final String ERROR_ZIP = "errors.zip";
    public static final String ERROR_FILEPATH = "errors.filePath";
    public static final String ERROR_SELF_CERTIFICATE = "errors.self.certificate";

    public static final String ERROR_NAMETAKEN = "errors.nameTaken";
    public static final String ERROR_CANCEL = "errors.cancel";
    public static final String ERROR_DETAIL = "errors.detail";
    public static final String ERROR_GENERAL = "errors.general";
    public static final String ERROR_TOKEN = "errors.token";
    public static final String ERROR_NONE = "errors.none";
    public static final String ERROR_CONVERSION = "errors.conversion";
    public static final String ERROR_PASSWORD_MISMATCH = "errors.password.mismatch";
    public static final String ERROR_TWOFIELDS = "errors.twofields";
    public static final String ERROR_EXISTING_USER = "errors.existing.user";

    public static final String USER_ADDED = "user.added";
    public static final String USER_DELETED = "user.deleted";
    public static final String USER_REGISTERED = "user.registered";
    public static final String USER_SAVED = "user.saved";
    public static final String USER_UPDATED_BYADMIN = "user.updated.byAdmin";
    public static final String NEWUSER_EMAIL_MESSAGE = "newuser.email.message";
    public static final String RELOAD_SUCCEEDED = "reload.succeeded";

    public static final String ERRORPAGE_TITLE = "errorPage.title";
    public static final String ERRORPAGE_HEADING = "errorPage.heading";
    public static final String ERROR404_TITLE = "404.title";
    public static final String ERROR404_MESSAGE = "404.message";
    public static final String ERROR403_TITLE = "403.title";
    public static final String ERROR403_MESSAGE = "403.message";

    static Map<String, String> messageMap = new HashMap<>();

    static {
        addToMap(ERROR_MAXLENGTH, "{0} has a maximum length of {1}.");
        addToMap(ERROR_MINLENGTH, "{0} can not be less than {1} characters.");
        addToMap(ERROR_RANGE, "{0} is not in the range {1} through {2}.");

        addToMap(ERROR_INVALID, "{0} is invalid.");
        addToMap(ERROR_BYTE, "{0} must be a byte.");
        addToMap(ERROR_DATE, "{0} is not a date.");
        addToMap(ERROR_DOUBLE, "{0} must be a double.");
        addToMap(ERROR_FLOAT, "{0} must be a float.");
        addToMap(ERROR_INTEGER, "{0} must be a number.");
        addToMap(ERROR_LONG, "{0} must be a long.");
        addToMap(ERROR_SHORT, "{0} must be a short.");

        addToMap(ERROR_URL, "{0} is an invalid url.");
        addToMap(ERROR_REQUIRED, "{0} is a required field.");
        addToMap(ERROR_CREDITCARD, "{0} is not a valid credit card number.");
        addToMap(ERROR_EMAIL, "{0} is an invalid e-mail address.");
        addToMap(ERROR_PHONE, "{0} is an invalid phone number.");
        addToMap(ERROR_ZIP, "{0} is an invalid zip code.");
        addToMap(ERROR_FILEPATH, "{0} is not a valid file.");
        addToMap(ERROR_SELF_CERTIFICATE, "Instructions for importing a self-signed certificate can be found <a target=\"_blank\" " +
                "href=\"https://github.com/denimgroup/threadfix/wiki/Importing-Self-Signed-Certificates\">here");

        addToMap(ERROR_NAMETAKEN, "That name is already taken.");
        addToMap(ERROR_CANCEL, "Operation cancelled.");
        addToMap(ERROR_DETAIL, "{0}");
        addToMap(ERROR_GENERAL, "The process did not complete. Details should follow.");
        addToMap(ERROR_TOKEN, "Request could not be completed. Operation is not in sequence.");
        addToMap(ERROR_NONE, "No error message was found, check your server logs.");
        addToMap(ERROR_PASSWORD_MISMATCH, "Invalid username and/or password, please try again.");
        addToMap(ERROR_CONVERSION, "An error occurred while converting web values to data values.");
        addToMap(ERROR_TWOFIELDS, "The {0} field has to have the same value as the {1} field.");
        addToMap(ERROR_EXISTING_USER, "This username ({0}) or e-mail address ({1}) already exists.  Please try a different username.");

        addToMap(USER_ADDED, "User information for {0} has been added successfully.");
        addToMap(USER_DELETED, "User Profile for {0} has been deleted successfully.");
        addToMap(USER_REGISTERED, "You have successfully registered for access to this application.");
        addToMap(USER_SAVED, "Your profile has been updated successfully.");
        addToMap(USER_UPDATED_BYADMIN, "User information for {0} has been successfully updated.");
        addToMap(NEWUSER_EMAIL_MESSAGE, "{0} has created an AppFuse account for you.  Your username and password information is below.");
        addToMap(RELOAD_SUCCEEDED, "Reloading options completed successfully.");

        addToMap(ERRORPAGE_TITLE, "An error has occurred");
        addToMap(ERRORPAGE_HEADING, "Yikes!");
        addToMap(ERROR404_TITLE, "Not Found");
        addToMap(ERROR404_MESSAGE, "The page you requested was not found.  You might try returning to the <a href=\"{0}\">Main Page</a>.");
        addToMap(ERROR403_TITLE, "Access Denied");
        addToMap(ERROR403_MESSAGE, "Your current role does not allow you to view this page.  Please contact your system administrator if you believe you should have access.");

    }

    private static void addToMap(String key, String value) {
        if (!messageMap.containsKey(key)) {
            messageMap.put(key, value);
        }
    }

    public static String getValue(String key, String[] args) {
        String value = messageMap.get(key);
        if (args == null || args.length == 0 || value == null)
            return value;
        else {
            for (int i=0; i<args.length; i++) {
                value = value.replace("{" + i + "}", args[i]);
            }
        }
        return value;
    }
}
