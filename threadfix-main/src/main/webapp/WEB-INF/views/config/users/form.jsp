<%@ include file="/common/taglibs.jsp"%>

<form:form id="nameAndPasswordForm${ user.id }" modelAttribute="user" name="user" action="${ fn:escapeXml(saveUrl) }">
	<table class="dataTable">
		<tr>
			<td class="no-color">Username</td>
			<td class="no-color">
				<form:input id="nameInput${ user.name.replaceAll(' ', '-') }" path="name" cssClass="focus" size="30" maxlength="25" value="${user.name}"/>
			</td>
			<td class="no-color" style="padding-left: 5px">
				<form:errors path="name" cssClass="errors" />
			</td>
		</tr>
		<tr>
			<td class="no-color">Password</td>
			<td class="no-color">
				<form:password class="password${ status.count }" id="passwordInput${ user.name.replaceAll(' ', '-') }"
                               path="unencryptedPassword"
                        onchange="checkPasswordHandlers('${ user.name }')"/>
			</td>
			<td class="no-color" style="padding-left: 5px">
				<form:errors id="passwordInputError${ user.id }" path="password" cssClass="errors"/>
                <span class="hide errors" id="passwordInputErrorSpan${ user.name.replaceAll(' ', '-') }">Password has a minimum length of 12.</span>
			</td>
		</tr>
		<tr>
			<td class="no-color">Confirm</td>
			<td class="no-color">
				<form:password class="password${ status.count }" id="passwordConfirmInput${ user.name.replaceAll(' ', '-') }" path="passwordConfirm" />
			</td>
		</tr>
		<c:if test="${ ldap_plugin }">
		<tr>
			<td class="no-color">LDAP user</td>
			<td class="no-color" style="text-align: left;">
				<form:checkbox class="ldapCheckbox"
					data-target-class="password${ status.count }"
					id="isLdapUserCheckbox${ status.count }"
					path="isLdapUser"
					data-value="${user.isLdapUser}" />
			</td>
		</tr>
		</c:if>
		<security:authorize ifAllGranted="ROLE_ENTERPRISE">
		<tr>
			<td class="no-color">Global Access</td>
			<td class="no-color" style="text-align: left;">
				<form:checkbox onclick="toggleRoles('${ status.count }')"
					id="hasGlobalGroupAccessCheckbox${ status.count }"
					class="globalAccessCheckBox"
					path="hasGlobalGroupAccess"
					data-value="${user.hasGlobalGroupAccess}"/>
			</td>
		</tr>
		<tr>
			<td class="no-color">Role for Global Access</td>
			<td class="no-color" style="text-align: left;">
				<form:select id="roleSelect${ user.name.replaceAll(' ', '-') }" path="globalRole.id">
					<form:option value="0" label="Read Access" />
					<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
				</form:select>

				<c:if test="${ not user.hasGlobalGroupAccess }">
					<script>$("#roleSelect<c:out value="${ user.name.replaceAll(' ', '-') }"/>").attr("disabled","disabled");</script>
				</c:if>
				<c:if test="${ user.hasGlobalGroupAccess }">
					<script>$("#roleSelect<c:out value="${ user.name.replaceAll(' ', '-') }"/>").val(<c:out value='${ user.globalRole.id }'/>);</script>
				</c:if>
				<c:if test="${ empty user.globalRole }">
					<script>$("#roleSelect<c:out value="${ user.name.replaceAll(' ', '-') }"/>").val(0);</script>
				</c:if>
			</td>
			<td class="no-color" style="border: 0px solid black; background-color: white; padding-left: 5px">
				<form:errors id="hasGlobalGroupAccessErrors${ user.name.replaceAll(' ', '-') }" path="hasGlobalGroupAccess" cssClass="errors" />
			</td>
		</tr>
		</security:authorize>
	</table>

</form:form>
