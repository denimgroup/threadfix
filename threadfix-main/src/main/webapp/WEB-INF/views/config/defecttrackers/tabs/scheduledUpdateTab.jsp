<%@ include file="/common/taglibs.jsp"%>

<tab id="scheduledUpdateTab" ng-controller="ScheduledDefectTrackerUpdateTabController" heading="{{ heading }}">

    <div ng-show="successMessage" class="alert alert-success">
        <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
        {{ successMessage }}
    </div>
    <div ng-show="errorMessage" class="alert alert-danger">
        <button class="close" ng-click="errorMessage = undefined" type="button">&times;</button>
        {{ errorMessage }}
    </div>

    <c:if test="${ canManageDefectTrackers }">
        <div style="margin-top:10px;margin-bottom:7px;">
            <a id="addUpdateQueueLink" class="btn" ng-click="openNewScheduledUpdateModal()">Schedule New Update</a>
        </div>
    </c:if>

    <div id="updateQueueDiv${ application.id }">
        <table class="table">
            <thead>
            <tr>
                <th>ID</th>
                <th>Time</th>
                <th>Frequency</th>
                <th>Cron Expression</th>
                <c:if test="${ canManageDefectTrackers }">
                    <th class="centered last"></th>
                </c:if>
            </tr>
            </thead>
            <tbody>
            <tr ng-hide="scheduledUpdates" class="bodyRow">
                <td id="noScheduledUpdatesFoundMessage" colspan="5" style="text-align:center;">No Scheduled Updates found.</td>
            </tr>
            <tr class="bodyRow" ng-repeat="scheduledUpdate in scheduledUpdates">
                <td id="scheduledUpdateId{{ scheduledUpdate.timeStringId }}"> {{ scheduledUpdate.id }} </td>
                <td id="scheduledUpdateDay{{ scheduledUpdate.timeStringId }}">
                    <span ng-hide="scheduledUpdate.scheduleType == 'CRON'">
                        {{ scheduledUpdate.timeString }}
                    </span>
                </td>
                <td id="scheduledUpdateFrequency{{ scheduledUpdate.timeStringId }}">
                    <span ng-hide="scheduledUpdate.scheduleType == 'CRON'">
                        {{ scheduledUpdate.frequency }}
                    </span>
                </td>
                <td id="scheduledUpdateCronExpression">
                    <span ng-show="scheduledUpdate.scheduleType == 'CRON'">
                        {{ scheduledUpdate.cronExpression }}
                    </span>
                </td>
                <c:if test="${ canManageDefectTrackers }">
                    <td class="centered">
                        <a  id="scheduledUpdateDeleteButton{{ scheduledUpdate.timeStringId }}" class="btn btn-danger" ng-click="deleteScheduledUpdate(scheduledUpdate)">Delete</a>
                    </td>
                </c:if>
            </tr>
            </tbody>
        </table>
    </div>
</tab>