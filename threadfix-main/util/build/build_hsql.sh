cd threadfix/threadfix-upgrade/hsql-upgrade
mvn clean compile assembly:single
cd /cygdrive/c/Build
cp /cygdrive/c/ThreadFix/threadfix/threadfix-upgrade/hsql-upgrade/target/threadfix-hsql-update-1.2-jar-with-dependencies.jar ThreadFixBase/database/dbupdate.jar
cp /cygdrive/c/ThreadFix/threadfix/threadfix-upgrade/hsql-upgrade/resources/*.sql ThreadFixBase/database/
