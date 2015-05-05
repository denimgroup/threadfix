package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.framework.impl.rails.model.RailsController;
import com.denimgroup.threadfix.framework.impl.rails.model.RailsControllerMethod;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Created by sgerick on 4/27/2015.
 */
public class RailsControllerParserTest {

    private static final String[][] RAILSGOAT_CONTROLLERS = new String [][]{
            //  {"ctrl", "method1", "method2", "method3"},
            {"Admin", "dashboard","analytics","get_all_users","get_user","update_user","delete_user"},
            {"BenefitForms", "index","download","upload"},
            {"Users", "new","create","account_settings","update"},
            {"Messages", "index","show","destroy","create"},
    };
    private static final String[][] RAILSGOAT_USERS_CONTROLLER = new String [][]{
            //  {"method", "param1", "param2", "param3"},
            {"new"},
            {"create","user.email","user.admin","user.first_name","user.last_name","user.user_id","user.password",
                    "user.password_confirmation","user.skip_user_id_assign","user.skip_hash_password"},
            {"account_settings"},
            {"update", "user", "user.password", "user.password_confirmation"}
    };
    private static final String[][] RAILSGOAT_MESSAGES_CONTROLLER = new String [][]{
            //  {"method", "param1", "param2", "param3"},
            {"index"},
            {"show","id"},
            {"destroy","id"},
            {"create", "message.creator_id","message.message","message.read","message.receiver_id"}
    };

    private List<RailsController> railsControllers;


    @Test
    public void testRailsGoatControllerParser() {
        File f = new File("C:\\SourceCode\\railsgoat-master");
        assert(f.exists());
        assert(f.isDirectory());
        //System.err.println("parsing "+f.getAbsolutePath() );
        railsControllers = (List<RailsController>) RailsControllerParser.parse(f);
        //System.err.println(System.lineSeparator() + "Parse done." + System.lineSeparator());

        checkControllers(RAILSGOAT_CONTROLLERS);
        checkController("Users", RAILSGOAT_USERS_CONTROLLER);
        checkController("Messages",RAILSGOAT_MESSAGES_CONTROLLER);
    }

    private void checkControllers(String[][] testControllers) {
        for (String[] testCtrl : testControllers) {
            String testCtrlName = testCtrl[0];
            RailsController rc = getRailsControllerByName(testCtrlName);
            assertTrue("Controller not found: " + testCtrlName, (rc != null) );
            for (int i=1; i < testCtrl.length; i++) {
                String testCtrlMethodName = testCtrl[i];
                boolean found = false;
                for (RailsControllerMethod rcm : rc.getControllerMethods()) {
                    if (testCtrlMethodName.equalsIgnoreCase(rcm.getMethodName())) {
                        found = true;
                        break;
                    }
                }
                assertTrue("Controller.method not found: " + testCtrlName.concat(".").concat(testCtrlMethodName),
                        found);
            }
        }
    }

    private void checkController(String ctrlName, String[][] testController) {
        RailsController rc = getRailsControllerByName(ctrlName);
        assertTrue("Controller not found: " + ctrlName, (rc != null) );
        for (String[] testMethod : testController) {
            boolean methodFound = false;
            String testMethodName = testMethod[0];
            for (RailsControllerMethod rcm : rc.getControllerMethods()) {
                String methodName = rcm.getMethodName();
                if (testMethodName.equals(methodName)) {
                    methodFound = true;
                    for (int i=1; i < testMethod.length; i++) {
                        String testParam = testMethod[i];
                        assertTrue("Controller.method[:param] not found: "
                                    + ctrlName.concat(".").concat(testMethodName)
                                    + "[" + testParam +  "]",
                                rcm.getMethodParams().contains(testParam));
                    }
                    break;
                }
            }
            assertTrue("Controller.method not found: " + ctrlName.concat(".").concat(testMethodName),
                    methodFound);
        }
    }

    private RailsController getRailsControllerByName(String ctrlName) {
        RailsController rcReturn = null;
        for (RailsController rc : railsControllers) {
            if (ctrlName.equalsIgnoreCase(rc.getControllerName())) {
                rcReturn = rc;
                break;
            }
        }
        return rcReturn;
    }


}

