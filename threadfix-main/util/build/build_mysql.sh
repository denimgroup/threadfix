cd threadfix-source/threadfix-upgrade/mysql-upgrade
mvn clean compile assembly:single
cd ~/Documents/Build
cp threadfix-source/threadfix-upgrade/mysql-upgrade/target/threadfix-mysql-update-1.2-jar-with-dependencies.jar threadfix_1_2_vm_upgrade/dbupdate.jar
cp threadfix-source/threadfix-upgrade/mysql-upgrade/src/resources/*.sql threadfix_1_2_vm_upgrade/
cp threadfix-source/threadfix-upgrade/mysql-upgrade/src/resources/fabfile.py threadfix_1_2_vm_upgrade/

/Applications/Ez7z.app/Contents/Resources/7za a threadfix_1_2_vm_upgrade.zip threadfix_1_2_vm_upgrade

cp threadfix_1_2rc3_vm_upgrade.zip /Volumes/Documents/ThreadFix
