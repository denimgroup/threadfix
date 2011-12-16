<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/> Path</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> Path</h2>

	<h3>Path</h3>
	
	<c:choose>
		<c:when test="${ fn:length(pathTree.printout ) == 1 }">
			<p>Listing <c:out value="${ fn:length(pathTree.printout ) }"/> path from <c:out value="${ fn:length(application.scans) }"/> scan(s)</p>
		</c:when>
		<c:otherwise>
			<p>Listing <c:out value="${ fn:length(pathTree.printout ) }"/> paths from <c:out value="${ fn:length(application.scans) }"/> scan(s)</p>
		</c:otherwise>
	</c:choose>
	<br/>
	Please select the application name from here:
	<br/>
	<br/>
	
<c:choose>
	<c:when test="${ empty application.vulnerabilities }">
		<p> No vulnerabilities found.</p>
	</c:when>
	<c:otherwise>
		<spring:url value="" var="emptyUrl"></spring:url>
		<form:form modelAttribute="application" method="post" autocomplete="off" action="${ fn:escapeXml( emptyUrl) }">
			<table class="formattedTable sortable" id="anyid">
				<thead>
					<tr>
						<th class="first" colspan="${ pathTree.depth }">Path</th>
					</tr>
				</thead>
				<tbody>
				<c:forEach var="path" items="${pathTree.printout}">
					<tr class="bodyRow">
						<spring:url value="{appId}/path/hint" var="hintUrl">
							<spring:param name="appId" value="${ application.id }"/>
						</spring:url>
						<c:forEach var="str" items="${ path }">
							<c:choose>
								<c:when test="${ empty str }">
									<td><c:out value="${ str }"/></td>
								</c:when>
								<c:otherwise>
									<td>
										<form:radiobutton path="projectRoot" name="hint" value="${ str }"/>
										<c:out value="${ str }"/>
									</td>
								</c:otherwise>
							</c:choose>
						</c:forEach>
					</tr>
				</c:forEach>
				</tbody>
				<tfoot>
					<tr class="footer">
						<td colspan="${ pathTree.depth }" class="pagination" style="text-align:right"></td>
					</tr>
				</tfoot>
			</table>
			<input type="submit" value="Add Application Root" />
		</form:form>
	</c:otherwise>
</c:choose>
</body>