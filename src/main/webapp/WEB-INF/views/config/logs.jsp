<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Logs</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/toggle.js"></script>
</head>

<body>
	<h3>Log List (Click to expand)</h3>
		
	<c:forEach var="log" items="${ exceptionLogList }">
	<a href="javascript:toggleid('<c:out value="${ log.id }"/>');">
		
		<fmt:formatDate value="${log.time.time}" type="both" dateStyle="short" timeStyle="medium" /> 
			-- <c:out value="${ log.UUID }"/>
			-- <c:out value="${ log.type }"/><br/>
		 </a>
			
		<div id="${ log.id }" style="display:none;">
			<pre><c:out value="${ log.exceptionStackTrace }"/></pre>
		</div>
	</c:forEach>
</body>