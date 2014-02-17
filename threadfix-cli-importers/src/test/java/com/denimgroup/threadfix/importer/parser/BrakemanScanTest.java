package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

import static com.denimgroup.threadfix.importer.TestConstants.*;

public class BrakemanScanTest extends TransactionalTest {

    public final static String[][] brakemanResults = new String [][] {
            {XSS, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/index.html.erb", "User.new"},
            {XSS, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/views/users/results.html.erb", "null"},
            {OS_INJECTION, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
            {OS_INJECTION, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
            {OS_INJECTION, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user][:password]"},
            {SQLI, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:query]"},
            {OPEN_REDIRECT, "Critical", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params"},
            {CSRF, "High", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/application_controller.rb", "null"},
            {EXTERNAL_CONTROL_OF_PARAM, "High", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
            {EXTERNAL_CONTROL_OF_PARAM, "High", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "params[:post]"},
            {EXTERNAL_CONTROL_OF_PARAM, "High", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
            {EXTERNAL_CONTROL_OF_PARAM, "High", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "params[:user]"},
            {ARGUMENT_INJECTION, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
            {ARGUMENT_INJECTION, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/models/user.rb", "null"},
            {FORCED_BROWSING, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/config/routes.rb", "null"},
            {EXTERNAL_CONTROL_OF_PARAM, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/post, user.rb", "null"},
            {OPEN_REDIRECT, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/posts_controller.rb", "Post.find(params[:id])"},
            {OPEN_REDIRECT, "Medium", "C:/Users/mcollins/Downloads/presidentbeef-worst-forums-ever-8902d1b/presidentbeef-worst-forums-ever-8902d1b/app/controllers/users_controller.rb", "User.find(params[:id])"},
    };

    @Test
    public void brakemanScanTest() {
        ScanComparisonUtils.compare(brakemanResults, ScanLocationManager.getRoot() +
                "Static/Brakeman/brakeman.json");
    }
}
