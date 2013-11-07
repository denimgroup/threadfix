cd threadfix-scanagent
mvn clean compile assembly:single
cd ../Build

cp ../threadfix-scanagent/target/threadfix-scanagent-2.0M1-SNAPSHOT.jar .

cd ..