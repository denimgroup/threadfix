package com.denimgroup.threadfix.framework.impl.rails;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertTrue;

/**
 * Created by sgerick on 3/9/2015.
 */
public class RailsRoutesParserTest {

    private static final String[][] RAILSGOAT_ROUTES = new String [][] {
        {"GET", "/login"},
        {"GET", "/signup"},
        {"GET", "/logout"},
        {"GET", "/forgot_password"},
        {"GET", "/password_resets"},
        {"POST", "/password_resets"},
        {"GET", "/sessions"},
        {"POST", "/sessions"},
        {"GET", "/sessions/new"},
        {"GET", "/sessions/{id}/edit"},
        {"GET", "/sessions/{id}"},
        {"PUT", "/sessions/{id}"},
        {"DELETE", "/sessions/{id}"},
        {"GET", "/users/{id}/account_settings"},
        {"GET", "/users/{id}/retirement"},
        {"POST", "/users/{id}/retirement"},
        {"GET", "/users/{id}/retirement/new"},
        {"GET", "/users/{id}/retirement/{id}/edit"},
        {"GET", "/users/{id}/retirement/{id}"},
        {"PUT", "/users/{id}/retirement/{id}"},
        {"DELETE", "/users/{id}/retirement/{id}"},
        {"GET", "/users/{id}/paid_time_off"},
        {"POST", "/users/{id}/paid_time_off"},
        {"GET", "/users/{id}/paid_time_off/new"},
        {"GET", "/users/{id}/paid_time_off/{id}/edit"},
        {"GET", "/users/{id}/paid_time_off/{id}"},
        {"PUT", "/users/{id}/paid_time_off/{id}"},
        {"DELETE", "/users/{id}/paid_time_off/{id}"},
        {"GET", "/users/{id}/work_info"},
        {"POST", "/users/{id}/work_info"},
        {"GET", "/users/{id}/work_info/new"},
        {"GET", "/users/{id}/work_info/{id}/edit"},
        {"GET", "/users/{id}/work_info/{id}"},
        {"PUT", "/users/{id}/work_info/{id}"},
        {"DELETE", "/users/{id}/work_info/{id}"},
        {"GET", "/users/{id}/performance"},
        {"POST", "/users/{id}/performance"},
        {"GET", "/users/{id}/performance/new"},
        {"GET", "/users/{id}/performance/{id}/edit"},
        {"GET", "/users/{id}/performance/{id}"},
        {"PUT", "/users/{id}/performance/{id}"},
        {"DELETE", "/users/{id}/performance/{id}"},
        {"GET", "/users/{id}/benefit_forms"},
        {"POST", "/users/{id}/benefit_forms"},
        {"GET", "/users/{id}/benefit_forms/new"},
        {"GET", "/users/{id}/benefit_forms/{id}/edit"},
        {"GET", "/users/{id}/benefit_forms/{id}"},
        {"PUT", "/users/{id}/benefit_forms/{id}"},
        {"DELETE", "/users/{id}/benefit_forms/{id}"},
        {"GET", "/users/{id}/messages"},
        {"POST", "/users/{id}/messages"},
        {"GET", "/users/{id}/messages/new"},
        {"GET", "/users/{id}/messages/{id}/edit"},
        {"GET", "/users/{id}/messages/{id}"},
        {"PUT", "/users/{id}/messages/{id}"},
        {"DELETE", "/users/{id}/messages/{id}"},
        {"POST", "/users/{id}/pay/update_dd_info"},
        {"POST", "/users/{id}/pay/decrypted_bank_acct_num"},
        {"GET", "/users/{id}/pay"},
        {"POST", "/users/{id}/pay"},
        {"GET", "/users/{id}/pay/new"},
        {"GET", "/users/{id}/pay/{id}/edit"},
        {"GET", "/users/{id}/pay/{id}"},
        {"PUT", "/users/{id}/pay/{id}"},
        {"DELETE", "/users/{id}/pay/{id}"},
        {"GET", "/users"},
        {"POST", "/users"},
        {"GET", "/users/new"},
        {"GET", "/users/{id}/edit"},
        {"GET", "/users/{id}"},
        {"PUT", "/users/{id}"},
        {"DELETE", "/users/{id}"},
        {"GET", "/download"},
        {"POST", "/upload"},
        {"GET", "/tutorials/credentials"},
        {"GET", "/tutorials/injection"},
        {"GET", "/tutorials/xss"},
        {"GET", "/tutorials/broken_auth"},
        {"GET", "/tutorials/insecure_dor"},
        {"GET", "/tutorials/csrf"},
        {"GET", "/tutorials/misconfig"},
        {"GET", "/tutorials/exposure"},
        {"GET", "/tutorials/url_access"},
        {"GET", "/tutorials/insecure_components"},
        {"GET", "/tutorials/access_control"},
        {"GET", "/tutorials/ssl_tls"},
        {"GET", "/tutorials/redirects"},
        {"GET", "/tutorials/guard"},
        {"GET", "/tutorials/mass_assignment"},
        {"GET", "/tutorials/gauntlt"},
        {"GET", "/tutorials/logic_flaws"},
        {"GET", "/tutorials/metaprogramming"},
        {"GET", "/tutorials"},
        {"POST", "/tutorials"},
        {"GET", "/tutorials/new"},
        {"GET", "/tutorials/{id}/edit"},
        {"GET", "/tutorials/{id}"},
        {"PUT", "/tutorials/{id}"},
        {"DELETE", "/tutorials/{id}"},
        {"GET", "/schedule/get_pto_schedule"},
        {"GET", "/schedule"},
        {"POST", "/schedule"},
        {"GET", "/schedule/new"},
        {"GET", "/schedule/{id}/edit"},
        {"GET", "/schedule/{id}"},
        {"PUT", "/schedule/{id}"},
        {"DELETE", "/schedule/{id}"},
        {"GET", "/admin/{id}/dashboard"},
        {"GET", "/admin/{id}/get_user"},
        {"POST", "/admin/{id}/delete_user"},
        {"PUT", "/admin/{id}/update_user"},
        {"GET", "/admin/{id}/get_all_users"},
        {"GET", "/admin/{id}/analytics"},
        {"GET", "/admin"},
        {"POST", "/admin"},
        {"GET", "/admin/new"},
        {"GET", "/admin/{id}/edit"},
        {"GET", "/admin/{id}"},
        {"PUT", "/admin/{id}"},
        {"DELETE", "/admin/{id}"},
        {"GET", "/dashboard/home"},
        {"GET", "/dashboard/change_graph"},
        {"GET", "/dashboard"},
        {"POST", "/dashboard"},
        {"GET", "/dashboard/new"},
        {"GET", "/dashboard/{id}/edit"},
        {"GET", "/dashboard/{id}"},
        {"PUT", "/dashboard/{id}"},
        {"DELETE", "/dashboard/{id}"}
    };

    @Test
    public void testRailsGoatRoutesParser() throws Exception {

        RailsRoutesParser routesParser = new RailsRoutesParser("C:\\SourceCode\\railsgoat-master\\config\\routes.rb");
        List<String[]> railsgoatRoutes = routesParser.parse();
        compareRoutes(RAILSGOAT_ROUTES, railsgoatRoutes);
    }

    private void compareRoutes( String[][] testData, List<String[]> list) {
        boolean found;
        for (String[] testRoute : testData) {
            found = false;
            for (String[] foundRoute : list) {
                if (testRoute[0].equals(foundRoute[0]) && testRoute[1].equals(foundRoute[1])) {
                    found = true;
                    break;
                }
            }
            assertTrue("testRoute not found in returned list: " + testRoute[0] + ": " + testRoute[1], found);
        }
    }

}

