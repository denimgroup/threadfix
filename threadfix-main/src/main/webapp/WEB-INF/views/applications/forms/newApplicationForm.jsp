<script type="text/ng-template" id="newApplicationModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New Application
        </h4>
    </div>
    <div ng-form='form' class="modal-body input-group">
        <table class="modal-form-table">
            <tr class="left-align">
                <td>Name</td>
                <td>
					<input type='text' name='name' ng-model="application.name" required/>
                    <span class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
				</td>
            </tr>
            <tr class="left-align">
                <td>URL</td>
                <td>
					<input type='url' name='url' ng-maxlength='200' ng-model="application.url" required/>
                    <span class="errors" ng-show="form.url.$dirty && form.url.$error.required">URL is required.</span>
                    <span class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Maximum length is 200.</span>
			  	</td>
            </tr>
            <tr class="left-align">
                <td>Unique ID</td>
                <td>
                    <input type='text' style="margin-bottom:0px;" ng-model="application.uniqueId" id="uniqueIdInput{{ application.team.id }}" size="50" maxlength="255"
			  	</td>
            </tr>
            <tr class="left-align">
                <td>Team</td>
                <td>{{ application.team.name }}</td>
            </tr>
            <tr class="left-align">
                <td>Criticality</td>
                <td>
					<select style="margin-bottom:0px;" ng-model="application.applicationCriticality.id" id="criticalityId${organization.id}">
					    <c:forEach items="${applicationCriticalityList}" var="applicationCriticality">
						    <option value="<c:out value='${applicationCriticality.id}'/>"><c:out value='${applicationCriticality.name}'/></option>
                        </c:forEach>
					</select>
				</td>
            </tr>
            <tr>
                <td class="right-align">Application Type</td>
                <td class="left-align" >
					<select ng-model="application.frameworkType.id" id="frameworkTypeSelect{{ application.team.id }}">
					    <c:forEach items="${applicationTypes}" var="type">
						    <option value="<c:out value='${type.id}'/>"><c:out value='${type.displayName}'/></option>
                        </c:forEach>
                    </select>
				</td>
            </tr>
            <tr>
                <td class="right-align">Source Code URL:</td>
                <td class="left-align" >
					<input type='url' id="repositoryUrl{{ application.team.id }}" maxlength="250" ng-model="application.repositoryUrl"/>
				</td>
            </tr>
            <tr>
                <td class="right-align">Source Code Folder:</td>
                <td class="left-align" >
					<input type='text' id="repositoryFolder{{ application.team.id }}" maxlength="250" ng-model="application.repositoryFolder"/>
				</td>
            </tr>
        </table>
    </div>
    <div class="modal-footer">

        <button class="btn" ng-click="cancel()">Close</button>
        <button class="btn btn-primary" ng-click="ok()">Add Application</button>
    </div>
</script>
