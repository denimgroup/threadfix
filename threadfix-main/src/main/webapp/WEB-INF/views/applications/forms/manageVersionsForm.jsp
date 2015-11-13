<script type="text/ng-template" id="manageVersionsForm.html">
	<div class="modal-header">
		<h4>Versions</h4>
	</div>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf"%>

    <div class="modal-body">
        <table class="table table-striped">
            <thead>
            <tr>
                <th class="medium first">Version</th>
                <th class="short">Date</th>
                <c:if test="${ canManageApplications }">
                        <th class="short"></th>
                </c:if>
            </tr>
            </thead>
            <tbody id="userTableBody">
            <tr>
                <td colspan="3" ng-hide="config.versions.length > 0" style="text-align:center;" id="noVersionsMessage"> No Versions found.</td>
            </tr>
            <tr ng-repeat="version in config.versions">
                <td id="name{{ version.name | removeSpace }}">{{version.name}}</td>
                <td id="date{{ version.name | removeSpace }}">{{version.date | date}}</td>
                <c:if test="${ canManageApplications }">
                    <td> <a id="editModalButton{{ version.name | removeSpace }}" class="btn" ng-click="editVersion(version)">Edit/Delete</a> </td>
                </c:if>
            </tr>

            </tbody>
        </table>
    </div>

    <div class="modal-footer">
        <a id="closeModalButton" class="btn" ng-click="cancel()">Close</a>
        <c:if test="${ canManageApplications }">
            <button id="newVersion"
                    class="btn btn-primary"
                    ng-click="newVersion()">Create Version</button>
        </c:if>
    </div>

</script>
