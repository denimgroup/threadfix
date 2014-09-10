<script type="text/ng-template" id="permissionForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">{{ headerText }}</h4>
    </div>

    <div class="modal-body" ng-form="form">

        <table class="bordered padded">
            <tr>
                <td>Team</td>
                <td>
                    <select id="orgSelect" name="team" ng-model="object.team" not-zero="{{ object.team.id }}"
                            ng-change="setApps(object.team.applications); object.teamId = object.team.id;"
                            ng-options="team.name for team in config.teams">
                    </select>
                </td>
            </tr>
            <tr>
                <td>All apps?</td>
                <td>
                    <input type="checkbox" id="allAppsCheckbox" name="allApps" ng-model="object.allApps"/>
                </td>
            </tr>
            <tbody ng-show="!object.allApps && config.appList">
                <tr>
                    <td>Application</td>
                    <td>Role</td>
                </tr>
                <tr ng-repeat="app in config.appList">
                    <td>{{ app.name }}</td>
                    <td>
                        <select id="roleSelectApp{{ app.name }}" name="roleId" ng-model="app.role.id">
                            <option value="0" label="No Role" />
                            <option ng-selected="role.id === app.role.id" ng-repeat="role in config.roles" value="{{ role.id }}" >
                                {{ role.displayName }}
                            </option>
                        </select>
                    </td>
                </tr>
            </tbody>
            <tr ng-show="object.allApps">
                <td>Team Role</td>
                <td>
                    <select id="roleSelectTeam" name="roleId" ng-show="object.allApps" ng-model="object.role.id" ng-change="object.roleId = object.role.id">
                        <option value="0" label="Select a role" />
                        <option ng-selected="role.id === object.role.id" ng-repeat="role in config.roles" value="{{ role.id }}" >
                            {{ role.displayName }}
                        </option>
                    </select>
                </td>
            </tr>
        </table>

    </div>
    <div class="modal-footer">
        <span class="errors" style="float:left">{{ error }}</span>

        <a class="btn" ng-click="cancel()">Close</a>
        <button id="loadingButton"
                disabled="disabled"
                class="btn btn-primary"
                ng-show="loading">
            <span class="spinner"></span>
            Submitting
        </button>
        <button id="submit"
                ng-class="{ disabled : form.$invalid }"
                class="btn btn-primary"
                ng-mouseenter="form.name.$dirty = true"
                ng-hide="loading"
                ng-click="ok(form.$valid)">{{ buttonText }}</button>
    </div>
</script>
