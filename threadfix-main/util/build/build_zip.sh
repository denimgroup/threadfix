#rm ThreadFix_1_2.zip
#rm -r ThreadFix

cd threadfix-main
mvn package -DskipTests

cd ../Build
#rm ThreadFix_1_2.zip
rm -r ThreadFix
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix-backup.script
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFixBase/database/threadfix.script
cp ../threadfix-main/util/zip/* ThreadFixBase

cp -r ThreadFixBase ThreadFix

cp ../threadfix-main/target/threadfix-2.0M1-SNAPSHOT.war ThreadFix/tomcat/webapps/
mv ThreadFix/tomcat/webapps/threadfix-2.0M1-SNAPSHOT.war ThreadFix/tomcat/webapps/threadfix.war
cp ../threadfix-main/src/main/resources/threadfix-backup.script ThreadFix/database/
cp ThreadFix/database/threadfix-backup.script ThreadFix/database/threadfix.script

cd ..
