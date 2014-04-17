<table class="table">
	<thead>
		<tr>
			<th class="first"></th>
			<th>File Name</th>
			<th>Type</th>
			<th>Upload Date</th>
			<th class="centered">Download</th>
            <c:if test="${ canModifyVulnerabilities }">
			    <th class="centered last">Delete</th>
            </c:if>
			<th></th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
        <tr ng-hide="vulnerability.documents" class="bodyRow">
            <td colspan="7" style="text-align:center;">No files found.</td>
        </tr>
        <tr ng-show="vulnerability.documents" ng-repeat="document in vulnerability.documents" class="bodyRow">
            <td id="docNum{{ $index }}">{{ $index + 1 }}</td>
            <td id="name{{ $index }}">{{ document.name }}"/></td>
            <td id="type{{ $index }}">{{ document.type }}"/></td>
            <td id="uploadDate{{ $index }}" >{{ document.createdDate | date:'yyyy-MM-dd HH:mm' }}</td>
            <%--<td class="centered">--%>
                <%--<a class="btn" ng-click="downloadDoc(document)">Download</a>--%>
            <%--</td>--%>
            <td class="centered">
                <a target="_blank" class="btn" type="submit" ng-href="{{ base }}/download{{ csrfToken }}">Download</a>
            </td>
            <c:if test="${ canModifyVulnerabilities }">
                <%--<td class="centered">--%>
                    <%--<a class="btn btn-danger" ng-click="deleteDoc(document)">Delete</a>--%>
                <%--</td>--%>
                <td class="centered">
                    <a ng-hide="document.deleting" class="btn btn-danger" ng-click="deleteFile(document)">Delete</a>
                    <a ng-show="document.deleting" class="btn btn-danger" ng-disabled>
                        <span class="spinner"></span>
                        Deleting
                    </a>
                </td>
            </c:if>
            <%--<td>--%>
                <%--<a class="pointer" ng-click="viewDoc(document)" target="_blank">View File</a>--%>
            <%--</td>--%>
            <td>
                <a ng-href="{{ base }}/view{{ csrfToken }}" target="_blank">View File</a>
            </td>
        </tr>
	<%--<c:if test="${ empty vulnerability.documents }">--%>
		<%--<tr class="bodyRow">--%>
			<%--<td colspan="7" style="text-align:center;">No files found.</td>--%>
		<%--</tr>--%>
	<%--</c:if>--%>
	<%--<c:forEach var="document" items="${ vulnerability.documents }" varStatus="status">--%>
		<%--<tr class="bodyRow">--%>
			<%--<td id="docNum${ status.count }"><c:out value="${ status.count }" /></td>--%>
			<%--<td id="name${ status.count }"><c:out value="${ document.name }"/></td>--%>
			<%--<td id="type${ status.count }"><c:out value="${ document.type }"/></td>--%>
			<%--<td id="uploadDate${ status.count }" >--%>
				<%--<fmt:formatDate value="${ document.createdDate }" pattern="hh:mm:ss MM/dd/yyyy"/>--%>
			<%--</td>			--%>
			<%--<td class="centered"> --%>
				<%--<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/download" var="downloadUrl">--%>
					<%--<spring:param name="orgId" value="${ vulnerability.application.organization.id }"/>--%>
					<%--<spring:param name="appId" value="${ vulnerability.application.id }"/>--%>
					<%--<spring:param name="docId" value="${ document.id }"/>--%>
				<%--</spring:url>--%>
                <%--<a class="btn docDownload" data-download-form="downloadForm${ document.id }">Download</a>--%>
				<%--<form id="downloadForm${ document.id }" method="POST" action="${ fn:escapeXml(downloadUrl) }"></form>				--%>
			<%--</td>			--%>
			<%--<c:if test="${ canModifyVulnerabilities }">--%>
			<%--<td class="centered">--%>
				<%--<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/delete" var="deleteUrl">--%>
					<%--<spring:param name="orgId" value="${ vulnerability.application.organization.id }"/>--%>
					<%--<spring:param name="appId" value="${ vulnerability.application.id }"/>--%>
					<%--<spring:param name="docId" value="${ document.id }"/>--%>
				<%--</spring:url>--%>
                <%--<a class="btn btn-danger docDelete" data-delete-form="deleteForm${ document.id }">Delete</a>--%>
				<%--<form id="deleteForm${ document.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>					--%>
			<%--</td>--%>
			<%--<td>--%>
				<%--<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/view" var="viewUrl">--%>
					<%--<spring:param name="orgId" value="${ vulnerability.application.organization.id }"/>--%>
					<%--<spring:param name="appId" value="${ vulnerability.application.id }"/>--%>
					<%--<spring:param name="docId" value="${ document.id }"/>--%>
				<%--</spring:url>--%>
				<%--<a href="<c:out value="${ viewUrl }"/>" target="_blank">View File</a>--%>
			<%--</td>--%>
			<%--</c:if>--%>
		<%--</tr>--%>
	<%--</c:forEach>--%>
	</tbody>
</table>
