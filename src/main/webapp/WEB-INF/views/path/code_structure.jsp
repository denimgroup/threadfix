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
	<h2><c:out value="${ application.name }"/> Code Structure</h2>

	<!--[if IE]>
	This feature is not supported in Internet Explorer.
	<![endif]-->
	
	<![if !IE]>
	<c:if test="${ static != true}">
		There was not enough data to generate a Code Structure diagram. Upload a static scan and try again.
	</c:if>
	<c:if test="${ static == true}">
		<c:forEach var="finding" varStatus="status" items="${ application.findingList }">
			<input type="hidden" id="${ status.index }" value="${ finding.sourceFileLocation }"/>
		</c:forEach>
		<input type="hidden" id="size" value="${ fn:length(application.findingList) }"/>
		<canvas class="" style="opacity: 1;" id="sitemap"></canvas>
	</c:if>
	<![endif]>
</body>