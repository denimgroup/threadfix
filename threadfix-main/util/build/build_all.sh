sh build_hsql.sh
sh build_cli.sh

sh build_zip.sh

# omitting for now because we aren't supporting this for 2.0M1
#sh build_mysql.sh

sh zip_it_up.sh

rm /Volumes/Documents/ThreadFix/ThreadFix_2_0M1.zip
cp ThreadFix_2_0M1.zip /Volumes/Documents/ThreadFix/

