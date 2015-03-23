#!/bin/sh

SYSTEM=`uname -s`
CATALINA_HOME=./tomcat
PATH=${PATH}:./tomcat/bin
export CATALINA_HOME PATH

PWD=`pwd`
KEYSTORE_LOCATION=$PWD/tomcat/keystore

chmod +x ./$CATALINA_HOME/bin/*.sh
if [ $SYSTEM = "Darwin" ]; then
        export JAVA_HOME=$(/usr/libexec/java_home)
else

	if [ -z "$JAVA_HOME" ]; then
        	export JAVA_HOME=$(dirname $(readlink -f $(which javac)))/../
	fi

fi

echo $"Looking for a key in $KEYSTORE_LOCATION"

if [ ! -e $KEYSTORE_LOCATION ]; then
	$JAVA_HOME/bin/keytool -genkeypair -dname "cn=localhost, ou=Self-Signed, o=Threadfix Untrusted Certificate, c=US" -alias localhost -keypass changeit -keystore $KEYSTORE_LOCATION -storepass changeit -keyalg RSA
	if [ -e ./tomcat/keystore ]; then
		echo "Generated a keystore."
	else
		echo "Keystore Generation failed."
		exit 1
	fi
else
	echo "Using pre-generated keystore."
fi

case "$1" in
	start)
		mkdir $CATALINA_HOME/logs
		export CATALINA_OPTS="-Xms64m -Xmx1536m -XX:PermSize=256m -XX:MaxPermSize=256m"
		$CATALINA_HOME/bin/startup.sh
		tail -f $CATALINA_HOME/logs/catalina.out
	;;
	stop)
		$CATALINA_HOME/bin/shutdown.sh
	;;
	*)
		echo $"Usage: $prog {start|stop}"
		exit 1
	;;
esac
