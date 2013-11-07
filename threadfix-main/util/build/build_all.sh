cd ../../..
mvn clean install -DskipTests
#sh build_hsql.sh
sh threadfix-main/util/build/build_cli_endpoints.sh
#sh threadfix-main/util/build/build_scan_agent.sh
sh threadfix-main/util/build/build_cli.sh
sh threadfix-main/util/build/build_zap.sh
sh threadfix-main/util/build/build_zip.sh

# omitting for now because we aren't supporting this for 2.0M1
#sh build_mysql.sh

sh threadfix-main/util/build/zip_it_up.sh

#rm /Volumes/Documents/ThreadFix/ThreadFix_2_0M1.zip
#cp ThreadFix_2_0M1.zip /Volumes/Documents/ThreadFix/

