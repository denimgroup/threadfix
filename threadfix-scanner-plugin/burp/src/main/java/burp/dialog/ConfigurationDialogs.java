package burp.dialog;

import java.awt.*;

public class ConfigurationDialogs {
	
	public ConfigurationDialogs() {}
	
	public static boolean show(Component view) {

        boolean shouldContinue = ParametersDialog.show(view);
        
        if (shouldContinue) {
            shouldContinue = ApplicationDialog.show(view);
        }
        
        return shouldContinue;
	}

}
