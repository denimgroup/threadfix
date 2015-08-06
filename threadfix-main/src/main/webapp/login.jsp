<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ include file="/common/taglibs.jsp"%>

<html lang="en">
<head>
	<meta http-equiv="X-FRAME-OPTIONS" content="DENY"/>
	<title>ThreadFix</title>
    <cbs:cachebustscript src="/scripts/angular.min.js"/>
    <cbs:cachebustscript src="/scripts/angular-sanitize.min.js"/>
    <cbs:cachebustscript src="/scripts/login-controller.js"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/login.css"/>
</head>

<body ng-app="threadfix">
	<spring:url value="j_spring_security_check" var="loginUrl"/>
	<div style="position:absolute;left:50%;top:50%;margin-top:-100px;margin-left:-250px;width:500px;height:220px">
	<table style="width:500px;height:200px;border-width:1px;border-collapse:collapse;border-color:black;border-style:solid;">
		<tr style="width:500px;height:20px;background:#43678b;"><td></td></tr>
		<tr style="height:200px;background:#EFEFEF;"><td></td></tr>
	</table>
	</div>

    <div ng-controller="LoginController">
        <form method="post" action="${ fn:escapeXml(loginUrl) }" autocomplete="off" name="form">
            <!-- Attempts to change this will only result in the CSRF filter blocking the user -->
            <input type='hidden' name='spring-security-redirect' value='/dashboard'/>
            <div style="position:absolute;left:50%;top:50%;margin-left:-250px;margin-top:-191px;">
                <img src="<%=request.getContextPath()%>/images/ThreadFix_72.jpg" alt="Denim Group" width="177px" height="81px"/>
            </div>
            <c:if test="${SPRING_SECURITY_LAST_EXCEPTION.message =='Bad credentials'}">
                <div id="loginError" style="position:absolute;left:50%;top:50%;margin-left:-250px;margin-top:-68px;width:500px;text-align:center;color:red;font-weight:bold">
                    Error: Username or Password incorrect
                </div>
            </c:if>
            <c:if test="${SPRING_SECURITY_LAST_EXCEPTION.message =='Check logs'}">
                <div id="loginError" style="position:absolute;left:50%;top:50%;margin-left:-250px;margin-top:-68px;width:500px;text-align:center;color:red;font-weight:bold">
                    Error: Your database may have been created incorrectly.<br>Please check logs for more information.
                </div>
            </c:if>
            <div style="position:absolute;left:50%;top:50%;margin-left:-143px;margin-top:-32px;color:black;width:70px;text-align:right;">
                Username
            </div>
            <div style="position:absolute;left:50%;top:50%;margin-left:-63px; margin-top:-32px;">
                <input type="text" style="width:200px" id="username" class="textbox focus" name="j_username" required/>
                {{ test }}
            </div>
            <div style="position:absolute;left:50%;top:50%;margin-left:-143px;margin-top:9px;color:black;width:70px;text-align:right;">
                Password
            </div>
            <div style="position:absolute;left:50%;top:50%;margin-left:-63px; margin-top:9px;">
                <input type="password" style="width:200px" class="textbox" id="password" name="j_password" required/>
            </div>
            <div style="position:absolute;left:50%;top:50%;margin-left:-65px; margin-top:51px;">
                <button ng-class="{ disabled : form.$invalid }" id="login" style="width:130px;">Login</button>
            </div>

            <div style="position:absolute;left:50%;top:50%;margin-left:-75px; margin-top:132px;">
                <a href="http://www.denimgroup.com/" class="denim-group">
                    <img src="<%=request.getContextPath()%>/images/denim-group.png" alt="Denim Group" />
                </a>
            </div>
        </form>
    </div>
</body>
</html>
