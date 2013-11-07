cd ../zaproxy

svn update

cd build

ant

cd ../../threadfix/threadfix-scanner-plugin/zaproxy

cp -r ../../../zaproxy/lib .

cp ../../../zaproxy/build/zap/zap.jar .

javac -cp "zap.jar;lib/*.jar" src/com/denimgroup/threadfix/plugin/zap/action/*.java src/com/denimgroup/threadfix/plugin/zap/dialog/*.java src/org/zaproxy/zap/extension/threadfix/*.java

cd src

jar -cf threadfix-release-1.zap com org

cd ../../../Build

cp ../threadfix-scanner-plugin/zaproxy/src/threadfix-release-1.zap .

cd ..


