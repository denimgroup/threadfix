#!/bin/sh

# export PATH=$PATH:/Applications/HP_Fortify_3.50_SCA_and_Apps_Mac_x64/bin
export PATH=$PATH:/Applications/HP_Fortify/HP_Fortify_SCA_and_Apps_3.70/bin

echo Clean up
sourceanalyzer -b threadfix -clean

echo Add in code files
sourceanalyzer -b threadfix -jdk 1.6 -cp "/Users/dcornell/Documents/workspace-sts-3.1.0.RELEASE/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/stonemill/WEB-INF/lib/**/*.jar" "src/main/java/**/*.java"

echo Add in JSP and JavaScript files
sourceanalyzer -b threadfix -jdk 1.6 -cp "/Users/dcornell/Documents/workspace-sts-3.1.0.RELEASE/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/stonemill/WEB-INF/lib/**/*.jar" "src/main/webapp/**/*.jsp"
sourceanalyzer -b threadfix "src/main/webapp/**/*.js"

echo Add in config, SQL and other files
sourceanalyzer -b threadfix "src/main/java/**/*.properties"
sourceanalyzer -b threadfix "src/main/resources/**/*.properties"
sourceanalyzer -b threadfix "src/main/resources/**/*.xml"
sourceanalyzer -b threadfix "src/main/resources/**/*.sql"
sourceanalyzer -b threadfix "src/main/webapp/**/*.xml"

echo Run the scan
sourceanalyzer -b threadfix -Xmx4096M -scan -f threadfix.fpr
