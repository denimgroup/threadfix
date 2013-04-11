<%@ include file="/common/taglibs.jsp"%>

<form:form id="nameAndPasswordForm${ user.id }" modelAttribute="user" name="user" action="${ fn:escapeXml(saveUrl) }">
	<table class="dataTable">
		<tr>
			<td class="no-color">Name</td>
			<td class="no-color">
				<form:input id="nameInput" path="name" cssClass="focus" size="30" maxlength="25" value="${user.name}"/>
			</td>
			<td class="no-color" style="padding-left: 5px">
				<form:errors path="name" cssClass="errors" />
			</td>
		</tr>
		<tr>
			<td class="no-color">Password</td>
			<td class="no-color">
				<form:password id="passwordInput${ user.id }" path="unencryptedPassword" />
			</td>
			<td class="no-color" style="padding-left: 5px">
				<form:errors path="password" cssClass="errors" />
			</td>
		</tr>
		<tr>
			<td class="no-color">Confirm</td>
			<td class="no-color">
				<form:password id="passwordConfirmInput${ user.id }" path="passwordConfirm" />
			</td>
		</tr>
		<tr>
			<td class="no-color">LDAP user</td>
			<td class="no-color" style="text-align: left;">
				<form:checkbox onclick="togglePassword('${ user.id }')" id="isLdapUserCheckbox${ user.id }" 
					path="isLdapUser" value="${user.isLdapUser}" />
			</td>
		</tr>
		<tr>
			<td class="no-color">Global Access</td>
			<td class="no-color" style="text-align: left;">
				<form:checkbox onclick="toggleRoles('${ user.id }')" id="hasGlobalGroupAccessCheckbox${ user.id }" 
					path="hasGlobalGroupAccess" value="${user.hasGlobalGroupAccess}"/>
			</td>
		</tr>
		<tr>
			<td class="no-color">Role for Global Access</td>
			<td class="no-color" style="text-align: left;">
				<form:select id="roleSelect${ user.id }" path="globalRole.id">
					<form:option value="0" label="Read Access" />
					<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
				</form:select>
				
				<c:if test="${ not user.hasGlobalGroupAccess }">
					<script>$("#roleSelect<c:out value='${ user.id }'/>").attr("disabled","disabled");</script>
				</c:if>
				<c:if test="${ user.hasGlobalGroupAccess }">
					<script>$("#roleSelect<c:out value='${ user.id }'/>").val(<c:out value='${ user.globalRole.id }'/>)</script>
				</c:if>
			</td>
			<td class="no-color" style="border: 0px solid black; background-color: white; padding-left: 5px">
				<form:errors id="hasGlobalGroupAccessErrors" path="hasGlobalGroupAccess" cssClass="errors" />
			</td>
		</tr>
	</table>

</form:form>
