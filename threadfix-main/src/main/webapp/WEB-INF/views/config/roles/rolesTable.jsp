<table class="table table-striped">
	<thead>
		<tr>
			<th class="medium first">Name</th>
			<th class="short">Edit / Delete</th>
		</tr>
	</thead>
	<tbody>
        <tr ng-hide="roles">
            <td colspan="6" style="text-align:center;">No roles found.</td>
        </tr>
        <tr ng-repeat="role in roles" ng-show="roles">
            <td id="role{{ $index }}">
                {{ role.displayName }}
            </td>
            <td>
                <a id="editModalLink{{ $index }}" class="btn" ng-click="openEditModal(role)">
                    Edit / Delete
                </a>
            </td>
        </tr>
	</tbody>
</table>