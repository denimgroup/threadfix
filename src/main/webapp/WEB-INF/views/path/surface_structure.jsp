<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/> Attack Surface and Code Structure</title>
	<script type="text/javascript" src="<%=request.getContextPath() %>/scripts/arbor.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/jquery_002.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/jquery.js"></script>

    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/arbor.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/arbor-tween.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/arbor-graphics.js"></script>
    
    <script type="text/javascript" src="<%=request.getContextPath() %>/scripts/arbor-site.js"></script>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> Attack Surface Structure</h2>
	<!--[if IE]>
	This feature is not supported in Internet Explorer.
	<![endif]-->
	
	<![if !IE]>
	<c:if test="${ sufficientInformation == true }">
		<c:forEach var="vuln" varStatus="status" items="${ application.vulnerabilities }">
			<input type="hidden" id="${ status.index }" value="${ vuln.surfaceLocation.path }"/>
		</c:forEach>
		<input type="hidden" id="size" value="${ fn:length(application.vulnerabilities) }"/>
		<canvas class="" style="opacity: 1;" id="sitemap"></canvas>
	</c:if>
	<c:if test="${ sufficientInformation == false }">
		There was not enough information to generate a surface structure diagram. Please upload a valid scan.
	</c:if>
	<![endif]>
</body>
