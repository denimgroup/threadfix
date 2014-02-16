<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ include file="/common/taglibs.jsp"%>
<html lang="en">
<head>
	<%@ include file="/common/meta.jsp" %>
	<title><decorator:title/> | <spring:message code="webapp.name"/></title>

	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/reset-fonts-grids.css"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/bootstrap.min.css"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/main.css"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/jquery-ui.css"/>

    <script data-require="angular.js@*" data-semver="1.2.12" src="http://code.angularjs.org/1.2.12/angular.js"></script>
    <script src="http://angular-ui.github.io/bootstrap/ui-bootstrap-tpls-0.10.0.js"></script>


    <!--[if lt IE 7]>
		<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/ie6.css"/>
		<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/iepngfix_tilebg.js"></script>
		
	<![endif]-->	
    
	<decorator:head/>
</head>
<body ng-app='threadfix' ng-init='name="World"'
      <decorator:getProperty property="body.id" writeEntireProperty="true"/>
	  <decorator:getProperty property="body.class" writeEntireProperty="true"/>>
	<div id="wrapper">
		<div id="main">
			<jsp:include page="/common/header.jsp"/>
			<div class="top-corners corners">
				<div class="left corner"><!-- --></div>
				<div class="right corner"><!-- --></div>
				<div class="center"><!-- --></div>
			</div>
			<div id="main-content">
                Hello {{name}}!
				<decorator:body/>
			</div>			
			<div class="bottom-corners corners">
				<div class="left corner"><!-- --></div>
				<div class="right corner"><!-- --></div>
				<div class="center"><!-- --></div>
			</div>
		</div>
	</div>
	<jsp:include page="/common/footer.jsp"/>
	<jsp:include page="/common/delete.jsp"/>
</body>
</html>
