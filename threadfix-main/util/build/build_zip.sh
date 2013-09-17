rm ThreadFix_1_2rc2.zip

cd threadfix-source/threadfix-main
mvn package

cd ~/Documents/Build

cp -r ThreadFixBase ThreadFix

cp threadfix-source/threadfix-main/target/threadfix-0.0.1-SNAPSHOT.war ThreadFix/tomcat/webapps/threadfix.war

zip -r ThreadFix_1_2rc2.zip ThreadFix

