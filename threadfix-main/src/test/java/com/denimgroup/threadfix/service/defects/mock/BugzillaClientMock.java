package com.denimgroup.threadfix.service.defects.mock;

import com.denimgroup.threadfix.service.defects.utils.bugzilla.BugzillaClient;
import org.apache.xmlrpc.XmlRpcException;

import java.util.HashMap;
import java.util.Map;

import static junit.framework.Assert.assertTrue;
import static com.denimgroup.threadfix.service.defects.util.TestConstants.*;

/**
 * Created by denimgroup on 4/7/14.
 */
@SuppressWarnings("unchecked")
public class BugzillaClientMock implements BugzillaClient{

    ConnectionStatus status = ConnectionStatus.INVALID;

    public static final Map<String, Object[]> severities = new HashMap<>();
    public static final Map<String, Object[]> statuses = new HashMap<>();
    public static final Map<String, Object[]> priorities = new HashMap<>();
    public static final Map<String, Object[]> version = new HashMap<>();
    public static final Map<String, Object[]> components = new HashMap<>();

    public static final Map<String,String> versionMap = new HashMap<>();
    public static final Map<String, Object[]> products = new HashMap<>();
    public static final Map<String, Object[]> productMap = new HashMap<>();
    public static final Map<String, Integer> bugCreateMap = new HashMap<>();

    public static final Map<String, Object[]>defectList =  new HashMap<>();
    static {
        severities.put("values", new Object[]{"blocker", "critical", "major",
                "normal", "minor", "trivial", "enhancement"});
        statuses.put("values", new Object[]{"UNCONFIRMED", "CONFIRMED",
                "IN_PROGRESS", "RESOLVED", "VERIFIED"});
        priorities.put("values", new Object[]{"Highest", "High", "Normal",
                "Low", "Lowest", "---"});
        version.put("values", new Object[]{"unspecified"});
        components.put("values", new Object[]{"Sample Component"});

        products.put("ids", new Object[]{1, 2, 3 ,4});
        productMap.put("products", new Object[]{new HashMap<String, Object>(), new HashMap<String, Object>(),
                new HashMap<String, Object>(), new HashMap<String, Object>()});
        Object[] products = productMap.get("products");
        fillProductMap(products[0], "TestProduct", 1);
        fillProductMap(products[1], "QA Testing", 2);
        fillProductMap(products[2], "No Component Project", 3);
        fillProductMap(products[3], "For ThreadFix", 4);

        bugCreateMap.put("id", 110);
        versionMap.put("version","4.2.1");

        defectList.put("bugs", new Object[]{new HashMap<String, Object>(), new HashMap<String, Object>(),
                new HashMap<String, Object>(), new HashMap<String, Object>()});
        Object[] bugs = defectList.get("bugs");
        fillDefectList(bugs[0], "id", 1);
        fillDefectList(bugs[0], "is_open", false);
        fillDefectList(bugs[0], "status", "RESOLVED");
        fillDefectList(bugs[1], "id", 2);
        fillDefectList(bugs[1], "is_open", true);
        fillDefectList(bugs[1], "status", "CONFIRMED");
        fillDefectList(bugs[2], "id", 3);
        fillDefectList(bugs[3], "id", 4);
    }

    private static void fillProductMap(Object map, String name, int id) {
        ((HashMap<Object, Object>) map).put("name", name);
        ((HashMap<Object, Object>) map).put("id", id);
    }

    private static void fillDefectList(Object map, Object field, Object value) {
        ((HashMap<Object, Object>) map).put(field, value);
    }

    //TODO mock against BugzillaClientImpl.java, check return values for all methods

    @Override
    public ConnectionStatus configure(String url, String username, String password) {
        if (url.equals(BUGZILLA_BASE_URL + "/xmlrpc.cgi") && BUGZILLA_USERNAME.equals(username) &&
                BUGZILLA_PASSWORD.equals(password)) {
            status = ConnectionStatus.VALID;
            return ConnectionStatus.VALID;
        }

        status = ConnectionStatus.INVALID;
        return ConnectionStatus.INVALID;
    }

    @Override
    public Map<String, Integer> createBug(Map<String, String> bugMap) throws XmlRpcException {
        assertTrue("Status is still invalid.", status == ConnectionStatus.VALID);
        return bugCreateMap;
    }

    @Override
    public Object executeMethod(String method) throws XmlRpcException {
        return executeMethod(method, new Object[]{});
    }

    @Override
    public Object executeMethod(String method, Object... params) throws XmlRpcException {
        if (method.equals("Bugzilla.version")) {
            return versionMap;
        }

        assertTrue("Status is still invalid.", status == ConnectionStatus.VALID);
        if (method.equals("Product.get_accessible_products")) {
            return products;
        }

        if (method.equals("Product.get")) {
            if (params[0] instanceof HashMap<?, ?>) {
                Object[] names = (Object[]) ((HashMap<Object, Object>) params[0]).get("names");

                if (names == null) { // this means that the ids hash was passed in (probably) and we're in getProductNamesTest
                    return productMap;
                } else if (names.length == 1 && names[0].equals(BUGZILLA_PROJECT)) {
                    return productMap; // TODO return the expected map for valid project lookup
                } else { // this means it's the wrong project name
                    return null; // TODO return null or whatever
                }
            }
        }

        if (method.equals("Bug.legal_values")) {
            if (params[0] instanceof Map<?, ?>) {
                Map<String, String> map = (Map<String, String>) params[0];
                switch (map.get("field")) {
                    case "bug_severity":
                        return severities;
                    case "bug_status":
                        return statuses;
                    case "priority":
                        return priorities;
                    case "version":
                        return version;
                    case "component":
                        return components;
                 }
            }
        }

        if (method.equals("Bug.search") || method.equals("Bug.get")) {
            if (params[0] instanceof  Map<?,?>) {
                return defectList;
            }
        }

        return null;
    }

    @Override
    public boolean checkUrl(String url) {
        return url.equals(BUGZILLA_BASE_URL + "/xmlrpc.cgi");
    }
}
