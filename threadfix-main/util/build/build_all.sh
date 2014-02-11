cd ../../..
#mvn clean install -DskipTests

VERSION=2.0M2
ARTIFACTS_FOLDER=$(pwd)/artifacts

rm -r $ARTIFACTS_FOLDER
mkdir $ARTIFACTS_FOLDER

# Build endpoint cli
FOLDER_NAME=Build/ThreadFix-EndpointCLI-Beta-$VERSION
rm -r $FOLDER_NAME
mkdir $FOLDER_NAME
cp threadfix-cli-endpoints/target/threadfix-endpoint-cli-$VERSION-SNAPSHOT-jar-with-dependencies.jar $FOLDER_NAME/endpoints.jar
cp threadfix-cli-endpoints/README $FOLDER_NAME
cd  $FOLDER_NAME
zip  -q ThreadFix-EndpointCLI-Beta-$VERSION.zip -r ./*
cp ThreadFix-EndpointCLI-Beta-$VERSION.zip $ARTIFACTS_FOLDER
cd ../../

# Build scan agent
FOLDER_NAME=Build/ThreadFix-ScanAgent-Beta-$VERSION
rm -r $FOLDER_NAME
mkdir $FOLDER_NAME
cp threadfix-scanagent/target/threadfix-scanagent-$VERSION-SNAPSHOT-jar-with-dependencies.jar $FOLDER_NAME/scanagent.jar
cp threadfix-scanagent/README $FOLDER_NAME
cp threadfix-scanagent/scanagent.properties $FOLDER_NAME
cp threadfix-scanagent/zapStarter.jar $FOLDER_NAME
cp threadfix-scanagent/burp-agent.jar $FOLDER_NAME
cd  $FOLDER_NAME
zip  -q ThreadFix-ScanAgent-Beta-$VERSION.zip -r ./*
cp ThreadFix-ScanAgent-Beta-$VERSION.zip $ARTIFACTS_FOLDER
cd ../../

# Build ZAP plugin
FOLDER_NAME=Build/ThreadFix-ZapPlugin-Beta-$VERSION
rm -r $FOLDER_NAME
mkdir $FOLDER_NAME
cp threadfix-scanner-plugin/zaproxy/target/Zap-Plugin-2.0M2-SNAPSHOT-jar-with-dependencies.jar $FOLDER_NAME/threadfix-release-2.zap
cp threadfix-scanner-plugin/zaproxy/README $FOLDER_NAME
cd  $FOLDER_NAME
zip  -q ThreadFix-ZapPlugin-Beta-$VERSION.zip -r ./*
cp ThreadFix-ZapPlugin-Beta-$VERSION.zip $ARTIFACTS_FOLDER
cd ../../

# Build Burp plugin
FOLDER_NAME=Build/ThreadFix-BurpPlugin-Beta-$VERSION
rm -r $FOLDER_NAME
mkdir $FOLDER_NAME
cp threadfix-scanner-plugin/burp/target/threadfix-release-2-jar-with-dependencies.jar $FOLDER_NAME/threadfix-release-2.jar
cp threadfix-scanner-plugin/burp/README $FOLDER_NAME
cd  $FOLDER_NAME
zip  -q ThreadFix-BurpPlugin-Beta-$VERSION.zip -r ./*
cp ThreadFix-BurpPlugin-Beta-$VERSION.zip $ARTIFACTS_FOLDER
cd ../../

# Build IntelliJ--export intellij.zip to Build folder using "Prepare module for deployment"
FOLDER_NAME=Build/ThreadFix-IntelliJPlugin-Beta-$VERSION
rm -r $FOLDER_NAME
mkdir $FOLDER_NAME
cp Build/intellij.zip $FOLDER_NAME
cp threadfix-ide-plugin/intellij/README $FOLDER_NAME
cd  $FOLDER_NAME
zip  -q ThreadFix-IntelliJPlugin-Beta-$VERSION.zip -r ./*
cp ThreadFix-IntelliJPlugin-Beta-$VERSION.zip $ARTIFACTS_FOLDER
cd ../../

# Build Eclipse--export 
# FOLDER_NAME=Build/ThreadFix-EclipsePlugin-Beta-$VERSION
# rm -r $FOLDER_NAME
# mkdir $FOLDER_NAME
# cp Build/intellij.zip $FOLDER_NAME
# cp threadfix-ide-plugin/eclipse/README $FOLDER_NAME
# cd  $FOLDER_NAME
# zip  -q ThreadFix-EclipsePlugin-Beta-$VERSION.zip -r ./*
# cp ThreadFix-EclipsePlugin-Beta-$VERSION.zip $ARTIFACTS_FOLDER
# cd ../../

# build zip
cd Build

rm -r ThreadFix
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix-backup.script
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix.script
cp ../threadfix-main/util/zip/* ThreadFixBase

cp -r ThreadFixBase ThreadFix

cp ../threadfix-main/target/threadfix-$VERSION-SNAPSHOT.war ThreadFix/tomcat/webapps/
mv ThreadFix/tomcat/webapps/threadfix-$VERSION-SNAPSHOT.war ThreadFix/tomcat/webapps/threadfix.war
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFix/database/
cp ThreadFix/database/threadfix-backup.script ThreadFix/database/threadfix.script

zip -q ThreadFix_2_0M2.zip -r ThreadFix
mv ThreadFix_2_0M2.zip ../artifacts
cd ..

#rm /Volumes/Documents/ThreadFix/ThreadFix_2_0M1.zip
#cp ThreadFix_2_0M1.zip /Volumes/Documents/ThreadFix/

