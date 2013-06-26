<%@ include file="/common/taglibs.jsp"%>

<head>
    <title><fmt:message key="mainMenu.title"/></title>
    <meta name="heading" content="<fmt:message key='mainMenu.heading'/>"/>
    <meta name="menu" content="MainMenu"/>
</head>

${ message } <br/><br/>
<a href="../editapplication/edit.html?appId=${appId}">Edit Login Credentials</a><br/><br/>
<a href="../defecttracker/index.html">Edit Defect Trackers</a><br/><br/>
<a href="../defects/show.html?appId=${appId}">Back to Submission Page</a>