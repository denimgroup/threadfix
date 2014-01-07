package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.StreamTokenizer;

/**
 * Created by mac on 1/7/14.
 */
public class SpringJavaConfigurationChecker {

    public static boolean checkJavaFile(@NotNull File file) {

        boolean result = false;

        // This won't work with, for example, a Spring Scala project w/ Scala configuration
        if (file.exists() && file.isFile() && file.getName().endsWith(".java")) {
            WebMvcChecker tokenizer = new WebMvcChecker();
            EventBasedTokenizerRunner.run(file, tokenizer);
            result = tokenizer.isWebMvc();
        }

        return result;
    }

    static class WebMvcChecker implements EventBasedTokenizer {

        boolean hasConfiguration = false, hasEnableWebMvc = false, hasExtends = false,
                isWebMvcConfigurationSupportSubclass = false,
                done = false, arroba = false, passedClass = false;

        public boolean isWebMvc() {
            return isWebMvcConfigurationSupportSubclass || (hasConfiguration && hasEnableWebMvc);
        }

        @Override
        public boolean done() {
            return done;
        }

        @Override
        public void processToken(int type, int lineNumber, String stringValue) {

            if (type == StreamTokenizer.TT_WORD) {
                switch (stringValue) {
                    case "Configuration": hasConfiguration = arroba; break;
                    case "EnableWebMvc":  hasEnableWebMvc  = arroba; break;
                    case "extends":       hasExtends       = true;   break;
                    case "class":         passedClass      = true;   break;
                    case "WebMvcConfigurationSupport":
                        isWebMvcConfigurationSupportSubclass = hasExtends;
                        break;
                }
                arroba = false;
            } else if (type == ARROBA) {
                arroba = true;
            } else if (type == OPEN_CURLY) {
                done = passedClass;
            }
        }
    }

}
