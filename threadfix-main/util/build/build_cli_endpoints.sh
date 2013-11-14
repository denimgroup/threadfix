cd threadfix-cli-endpoints
mvn clean compile assembly:single
cd ../Build

cp ../threadfix-cli-endpoints/target/threadfix-endpoint-cli-2.0M1-SNAPSHOT-jar-with-dependencies.jar .

cd ..