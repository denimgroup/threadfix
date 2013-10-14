rm ThreadFix_1_2.zip
rm -r ThreadFix

cd threadfix-source/threadfix-main
mvn package

cd ~/Documents/Build

cp threadfix-source/threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix-backup.script
cp threadfix-source/threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix.script
cp threadfix-source/threadfix-main/util/zip/* ThreadFixBase

cp -r ThreadFixBase ThreadFix

cp threadfix-source/threadfix-main/target/threadfix-0.0.1-SNAPSHOT.war ThreadFix/tomcat/webapps/threadfix.war
cp threadfix-source/threadfix-main/src/main/resources/threadfix-backup.script ThreadFix/database/
cp ThreadFix/database/threadfix-backup.script ThreadFix/database/threadfix.script
