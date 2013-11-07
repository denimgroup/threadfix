cd threadfix-cli
mvn clean compile assembly:single
cd ../Build

cp ../threadfix-cli/target/threadfix-cli-2.0M1-SNAPSHOT-jar-with-dependencies.jar ThreadFixBase/command-line-interface/tfcli.jar

cd ..
