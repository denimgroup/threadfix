cd threadfix-source/threadfix-cli
mvn clean compile assembly:single
cd ~/Documents/Build

cp threadfix-source/threadfix-cli/target/ThreadFixCLI-0.0.1-SNAPSHOT-jar-with-dependencies.jar ThreadFixBase/command-line-interface/tfcli.jar
