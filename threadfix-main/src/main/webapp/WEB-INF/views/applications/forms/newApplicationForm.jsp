<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">New Application</h4>
</div>
<spring:url value="/organizations/{orgId}/modalAddApp" var="saveUrl">
	<spring:param name="orgId" value="${ organization.id }"/>
</spring:url>
<form:form style="margin-bottom:0px;" id="myAppForm${ organization.id }" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		<table>
			<tr class="left-align">
				<td style="padding:5px;">Name</td> 
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="nameInput${organization.name}" path="name" cssClass="focus" size="50" maxlength="60" />
				  	<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">URL</td>
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="urlInput${organization.name}" path="url" size="50" maxlength="255" />
				  	<form:errors path="url" cssClass="errors" />
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Unique ID</td>
				<td style="padding:5px;">
					<form:input style="margin-bottom:0px;" id="uniqueIdInput${organization.name}" path="uniqueId" size="50" maxlength="255" />
				  	<form:errors path="uniqueId" cssClass="errors" />
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Team</td>
				<td style="padding:5px;"><c:out value="${ organization.name }"/></td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Criticality</td>
				<td style="padding:5px;">
					<form:select style="margin-bottom:0px;" id="criticalityId${organization.name}" path="applicationCriticality.id">
						<form:options items="${applicationCriticalityList}" itemValue="id" itemLabel="name"/>
					</form:select>
					<form:errors path="applicationCriticality.id" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="right-align" style="padding:5px;">Application Type</td>
				<td class="left-align"  style="padding:5px;">
					<form:select path="frameworkType"
                                 id="frameworkTypeSelect${organization.name}"
						items="${ applicationTypes }"
						itemLabel="displayName"/>
				</td>
			</tr>
			<%--<tr>--%>
				<%--<td class="right-align" style="padding:5px;">Source Code URL:</td>--%>
				<%--<td class="left-align"  style="padding:5px;">--%>
					<%--<form:input id="repositoryUrl${organization.name}" maxlength="250" path="repositoryUrl"/>--%>
                    <%--<form:errors path="repositoryUrl" cssClass="errors" />--%>
				<%--</td>--%>
			<%--</tr>--%>


            <tr>
                <td class="right-align" style="padding:5px;">Source Code URL:</td>
                <td class="left-align"  style="padding:5px;">
                    <form:input id="repositoryUrl${organization.name}" maxlength="250" path="repositoryUrl"/>
                    <form:errors path="repositoryUrl" cssClass="errors" />
                </td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Source Code Revision:</td>
                <td class="left-align"  style="padding:5px;">
                    <form:input id="repositoryBranch${organization.name}" maxlength="250" path="repositoryBranch"/>
                    <form:errors path="repositoryBranch" cssClass="errors" />
                </td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Source Code UserName:</td>
                <td class="left-align"  style="padding:5px;">
                    <form:input id="repositoryUsername${organization.name}" maxlength="250" path="repositoryUserName"/>
                    <form:errors path="repositoryUserName" cssClass="errors" />
                </td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Source Code Password:</td>
                <td class="left-align"  style="padding:5px;">
                    <form:password id="repositoryPassword${organization.name}" showPassword="true" maxlength="250" path="repositoryPassword"/>
                    <form:errors path="repositoryPassword" cssClass="errors" />
                </td>
            </tr>

			<tr>
				<td class="right-align" style="padding:5px;">Source Code Folder:</td>
				<td class="left-align"  style="padding:5px;">
					<form:input id="repositoryFolder${organization.name}" maxlength="250" path="repositoryFolder"/>
					<form:errors path="repositoryFolder" cssClass="errors" />
				</td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitAppModal<c:out value="${organization.name}"/>" class="modalSubmit btn btn-primary"
			data-success-div="teamTable" data-success-click="teamCaret<c:out value="${organization.name}"/>">Add Application</a>
	</div>
</form:form>
