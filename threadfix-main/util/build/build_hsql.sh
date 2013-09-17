cd threadfix-source/threadfix-upgrade/hsql-upgrade
mvn clean compile assembly:single
cd ~/Documents/Build
cp threadfix-source/threadfix-upgrade/hsql-upgrade/target/threadfix-hsql-update-1.2-jar-with-dependencies.jar ThreadFixBase/database/dbupdate.jar
cp threadfix-source/threadfix-upgrade/hsql-upgrade/resources/*.sql ThreadFixBase/database/
