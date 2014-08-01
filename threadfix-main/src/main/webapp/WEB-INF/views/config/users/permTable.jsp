<%@ include file="/common/taglibs.jsp"%>

<table class="table" ng-show="maps">
    <thead>
    <tr>
        <th class="medium first">Team</th>
        <th class="medium">Application</th>
        <th class="medium">Role</th>
        <th class="short" style="text-align:center">Edit</th>
        <th class="short last" style="text-align:center">Delete</th>
    </tr>
    </thead>
    <tbody ng-repeat="map in maps" style="border-top: 0">
        <tr ng-show="map.allApps && map.active" class="bodyRow">
            <td id="teamName{{ map.organization.name }}">{{ map.organization.name }}</td>
            <td id="applicationName{{ map.organization.name }}">
                All
            </td>
            <td id="roleName{{ map.organization.name }}">
                {{ map.role.displayName }}
            </td>
            <td style="text-align:center">
                <a id="editAppMap{{ map.organization.name }}" class="btn" ng-click="edit(map)">
                    Edit
                </a>
            </td>
            <td style="text-align:center">
                <a class="btn" id="deleteAppMap{{ map.organization.name }}" ng-click="deleteTeam(map)">
                    Delete
                </a>
            </td>
        </tr>
        <tr ng-repeat="appMap in map.accessControlApplicationMaps" ng-show="!map.allApps && appMap.active" class="bodyRow">
            <td id="teamName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
                {{ map.organization.name }}
            </td>
            <td id="applicationName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
                {{ appMap.application.name }}
            </td>
            <td id="roleName{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}">
                {{ appMap.role.displayName }}
            </td>
            <td style="text-align:center">
                <a id="editAppMap{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}" class="btn" ng-click="edit(map)">
                    Edit
                </a>
            </td>
            <td style="text-align:center">
                <a class="btn" id="deleteAppMap{{ map.organization.name }}{{ appMap.application.name }}{{ appMap.role.displayName }}" ng-click="deleteApp(appMap)">
                    Delete
                </a>
            </td>
        </tr>
    </tbody>
</table>