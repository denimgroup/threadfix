
<h3 style="padding-top:5px;">Applications</h3>
<c:if test="${ canManageApplications }">
    <div style="margin-top:10px;margin-bottom:7px;">
        <c:if test="${ canAddApps}">
            <button class="btn" id="addApplicationModalButton" ng-click="openAppModal()">
                Add Application
            </button>
        </c:if>
        <c:if test="${ not canAddApps }">
            <button class="btn" id="addApplicationModalButton" ng-click="showAppLimitMessage(<c:out value="${ appLimit }"/>)">
                Add Application
            </button>
        </c:if>
    </div>
</c:if>

<div
    id="teamPaginationDiv{{ team.id }}">
        <div class="pagination" ng-init="page = 1">
            <input id="appSelectTypeahead{{team.id}}"
                   type="text"
                   class="form-control"
                   ng-model="goToApp"
                   placeholder="Application Search (press Enter)"
                   ng-enter="searchApps(goToApp)"/>

            <pagination ng-show="currentCount > numberToShow"
                    id="pagination{{team.id}}"
                        class="no-margin"
                        total-items="currentCount / numberToShow * 10"
                        max-size="5"
                        page="page"
                        first-text="&laquo;"
                        last-text="&raquo;"
                        boundary-links="true"
                        direction-links="false"
                        ng-model="page"
                        ng-click="updatePage(page, goToApp)"></pagination>
        </div>


</div>

<table class="table table-striped">
    <thead>
    <tr>
        <th class="medium first">Name</th>
        <th class="long">URL</th>
        <th class="short">Criticality</th>
        <th class="short">Open Vulns</th>
        <th class="short break-word-header" id="appHeaderCritical" generic-severity="Critical"></th>
        <th class="short break-word-header" id="appHeaderHigh" generic-severity="High"></th>
        <th class="short break-word-header" id="appHeaderMedium" generic-severity="Medium"></th>
        <th class="short break-word-header" id="appHeaderLow" generic-severity="Low"></th>
        <th class="short break-word-header" id="appHeaderInfo" generic-severity="Info"></th>
    </tr>
    </thead>
    <tbody id="applicationsTableBody">
    <tr ng-hide="loadingCurrentApps || currentApplications" class="bodyRow">
        <td colspan="9" style="text-align:center;">No applications found.</td>
    </tr>
    <tr ng-show="!loadingCurrentApps && currentApplications"
        ng-repeat="app in currentApplications" class="bodyRow">
        <td class="pointer ellipsis" ng-click="goToPage(app)" style="max-width:200px;" id="appName{{ $index }}">
            <a id="appLink{{ $index }}"> {{ app.name }} </a>
        </td>
        <td class="ellipsis" style="max-width:200px;" id="appUrl{{ $index }}"> {{ app.url }} </td>
        <td id="appCriticality{{ $index }}"> {{ app.applicationCriticality.name }} </td>
        <td id="appTotalVulns{{ $index }}"> {{ app.totalVulnCount }} </td>
        <td id="appCriticalVulns{{ $index }}"> {{ app.criticalVulnCount }} </td>
        <td id="appHighVulns{{ $index }}"> {{ app.highVulnCount }} </td>
        <td id="appMediumVulns{{ $index }}"> {{ app.mediumVulnCount }} </td>
        <td id="appLowVulns{{ $index }}"> {{ app.lowVulnCount }} </td>
        <td id="appInfoVulns{{ $index }}"> {{ app.infoVulnCount }} </td>
    </tr>
    </tbody>
</table>