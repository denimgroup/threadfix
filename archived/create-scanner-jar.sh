cd threadfix-main/target/classes
jar cvf scanners.jar com/denimgroup/threadfix/plugin/scanner/service/** mappings/
cd ../../
cp target/classes/scanners.jar src/main/resources
cd ..
