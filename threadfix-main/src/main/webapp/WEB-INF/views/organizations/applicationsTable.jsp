
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

<table class="table table-striped">
    <thead>
    <tr>
        <th class="medium first">Name</th>
        <th class="long">URL</th>
        <th class="short">Criticality</th>
        <th class="short">Open Vulns</th>
        <th class="short" generic-severity="Critical"></th>
        <th class="short" generic-severity="High"></th>
        <th class="short" generic-severity="Medium"></th>
        <th class="short" generic-severity="Low"></th>
        <th class="short" generic-severity="Info"></th>
    </tr>
    </thead>
    <tbody id="applicationsTableBody">
    <tr ng-hide="applications" class="bodyRow">
        <td colspan="9" style="text-align:center;">No applications found.</td>
    </tr>
    <tr ng-show="applications"
        ng-repeat="app in applications" class="bodyRow">
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