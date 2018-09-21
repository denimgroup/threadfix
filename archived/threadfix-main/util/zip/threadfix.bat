@echo on

@echo off
netstat -an  | find ":8080" | find "LISTENING" > NUL: && goto INUSE 
netstat -an  | find ":8443" | find "LISTENING" > NUL: && goto INUSESSL
echo Starting Threadfix
rem ...

@REM Clear the lib env var as it can hose tomcat
SET lib= 

@REM Set env vars for tomcat and java, use PWD as some machines don't have
@REM \. on their path
set PWD=%cd%
set CATALINA_HOME=%PWD%\tomcat
set CATALINA_OPTS=-Xms512m -Xmx1536m

for /f tokens^=2-5^ delims^=.-_^" %%j in ('java -fullversion 2^>^&1') do set "jver=%%j%%k%%l%%m"
echo jver is %jver%


if DEFINED JAVA_HOME (
	if %jver:~0,1% NEQ 1 (
		echo Could not determine Java version.  Java may not be included in PATH.  Using folder's Java 8.
		set JAVA_HOME="%PWD%\java"
	) else (
		echo Determined Java version.
		if %jver% LSS 17000 (
			echo Java version less than 7.  Using folder's Java 8.
			set JAVA_HOME="%PWD%\java"
			set CATALINA_OPTS=%CATALINA_OPTS% -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m
			goto :javaisset
		)
		if %jver% LSS 18000 (
			echo JAVA_HOME is Java 7.  Using Java 7.
			set CATALINA_OPTS=%CATALINA_OPTS% -XX:PermSize=256m -XX:MaxPermSize=256m
			goto :javaisset
		)
		set CATALINA_OPTS=%CATALINA_OPTS% -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m
		echo JAVA_HOME is Java 8.  Using Java 8.
		goto :javaisset
	)
) else (
	echo No JAVA_HOME found.  Using folder's Java 8.
	set JAVA_HOME="%PWD%\java"
)

:javaisset
if not exist tomcat\keystore echo Generating keystore
if not exist tomcat\keystore java\bin\keytool -genkeypair -dname "cn=localhost, ou=Self-Signed, o=Threadfix Untrusted Certificate, c=US" -alias localhost -keypass changeit -keystore tomcat\keystore -storepass changeit -keyalg RSA
if exist tomcat\keystore echo Keystore exists

@REM Run tomcat: must have quotes incase var has spaces in it
call "%CATALINA_HOME%\bin\startup.bat" start

echo 
echo If the Tomcat DOS shell quit immediately, it is likely that 
echo there is another service listening on port 8080 or 8443.
echo

ping -n 10 127.0.0.1 > NUL:

START "" "https://localhost:8443/threadfix"

goto END

:INUSE
echo There was already a service listening on port 8080. Please shut it down and try again.
ping -n 10 127.0.0.1 > NUL:
goto END

:INUSESSL
echo There was already a service listening on port 8443. Please shut it down and try again.
ping -n 10 127.0.0.1 > NUL:

:END