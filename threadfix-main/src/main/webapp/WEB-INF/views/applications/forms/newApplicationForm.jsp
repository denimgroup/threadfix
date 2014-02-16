<script type="text/ng-template" id="newApplicationModal.html">
    <div class="modal-header">
        <h3>New Application</h3>
    </div>
    <div class="modal-body">
        <table>
            <tr class="left-align">
                <td style="padding:5px;">Name</td>
                <td style="padding:5px;">
					<input ng-model="application.name"/>
				</td>
            </tr>
            <tr class="left-align">
                <td style="padding:5px;">URL</td>
                <td style="padding:5px;">
					<input ng-model="application.url"/>
			  	</td>
            </tr>
            <tr class="left-align">
                <td style="padding:5px;">Unique ID</td>
                <td style="padding:5px;">
                    <input style="margin-bottom:0px;" ng-model="application.uniqueId" id="uniqueIdInput{{ application.team.id }}" size="50" maxlength="255"
			  	</td>
            </tr>
            <tr class="left-align">
                <td style="padding:5px;">Team</td>
                <td style="padding:5px;">{{ application.team.name }}</td>
            </tr>
            <tr class="left-align">
                <td style="padding:5px;">Criticality</td>
                <td style="padding:5px;">
					<select style="margin-bottom:0px;" ng-model="application.applicationCriticality.id" id="criticalityId${organization.id}">
					    <c:forEach items="${applicationCriticalityList}" var="applicationCriticality">
						    <option value="<c:out value='${applicationCriticality.id}'/>"><c:out value='${applicationCriticality.name}'/></option>
                        </c:forEach>
					</select>
				</td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Application Type</td>
                <td class="left-align"  style="padding:5px;">
					<select ng-model="application.frameworkType.id" id="frameworkTypeSelect{{ application.team.id }}">
					    <c:forEach items="${applicationTypes}" var="type">
						    <option value="<c:out value='${type.id}'/>"><c:out value='${type.displayName}'/></option>
                        </c:forEach>
                    </select>
				</td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Source Code URL:</td>
                <td class="left-align"  style="padding:5px;">
					<input id="repositoryUrl{{ application.team.id }}" maxlength="250" ng-model="application.repositoryUrl"/>
				</td>
            </tr>
            <tr>
                <td class="right-align" style="padding:5px;">Source Code Folder:</td>
                <td class="left-align"  style="padding:5px;">
					<input id="repositoryFolder{{ application.team.id }}" maxlength="250" ng-model="application.repositoryFolder"/>
				</td>
            </tr>
        </table>
    </div>
    <div class="modal-footer">
        <button class="btn btn-primary" ng-click="ok()">Add Application</button>
        <button class="btn btn-warning" ng-click="cancel()">Cancel</button>
    </div>
</script>
