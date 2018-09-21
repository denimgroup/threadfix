<%@ include file="/common/taglibs.jsp"%>

<tab id="scheduledImportTab" ng-controller="ScheduledRemoteProviderImportTabController" heading="{{ heading }}">

    <div ng-show="successMessage" class="alert alert-success">
        <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
        {{ successMessage }}
    </div>
    <div ng-show="errorMessage" class="alert alert-danger">
        <button class="close" ng-click="errorMessage = undefined" type="button">&times;</button>
        {{ errorMessage }}
    </div>

    <c:if test="${ canManageRemoteProviders }">
        <div style="margin-top:10px;margin-bottom:7px;">
            <a id="addImportQueueLink" class="btn" ng-click="openNewScheduledImportModal()">Schedule New Import</a>
        </div>
    </c:if>

    <div id="importQueueDiv${ application.id }">
        <table class="table">
            <thead>
            <tr>
                <th>ID</th>
                <th>Time</th>
                <th>Frequency</th>
                <c:if test="${ canManageRemoteProviders }">
                    <th class="centered last"></th>
                </c:if>
            </tr>
            </thead>
            <tbody>
            <tr ng-hide="scheduledImports" class="bodyRow">
                <td id="noScheduledImportsFoundMessage" colspan="5" style="text-align:center;">No Scheduled Imports found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="scheduledImport in scheduledImports">
                <td id="scheduledImportId{{ scheduledImport.timeStringId }}"> {{ scheduledImport.id }} </td>
                <td id="scheduledImportDay{{ scheduledImport.timeStringId }}"> {{ scheduledImport.timeString }} </td>
                <td id="scheduledImportFrequency{{ scheduledImport.timeStringId }}"> {{ scheduledImport.frequency }} </td>
                <c:if test="${ canManageRemoteProviders }">
                    <td class="centered">
                        <a  id="scheduledImportDeleteButton{{ scheduledImport.timeStringId }}" class="btn btn-danger" ng-click="deleteScheduledImport(scheduledImport)">Delete</a>
                    </td>
                </c:if>
            </tr>
            </tbody>
        </table>
    </div>
</tab>