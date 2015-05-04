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
set CATALINA_OPTS=-Xms512m -Xmx1536m -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m
if DEFINED JAVA_HOME (
	"%JAVA_HOME%\bin\java" -version:1.8 -version > nul 2>&1
	if NOT ERRORLEVEL == 0 (
		echo Local JAVA_HOME is not Java 8, switching to threadfix JAVA_HOME
		set JAVA_HOME=%PWD%\java
	)
) else (
	set JAVA_HOME=%PWD%\java
)

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