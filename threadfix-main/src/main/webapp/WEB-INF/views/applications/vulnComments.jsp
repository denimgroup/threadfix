<table class="table">
	<thead>
		<tr>
			<th>User</th>
			<th>Date</th>
			<th class="last">Comment</th>
		<tr>
	</thead>
	<tbody>
        <tr ng-hide="vulnerability.vulnerabilityComments" class="bodyRow">
            <td colspan="4" style="text-align:center;">No comments found.</td>
        </tr>
        <tr ng-show="vulnerability.vulnerabilityComments" ng-repeat="comment in vulnerability.vulnerabilityComments" class="bodyRow left-align">
            <td id="commentUser{{ $index }}">{{ comment.username }}</td>
            <td id="commentDate{{ $index }}">{{ comment.time | date:'yyyy-MM-dd HH:mm' }}</td>
            <td id="commentText{{ $index }}">
                <div class="vuln-comment-word-wrap">
                    {{ comment.comment }}
                </div>
            </td>
        </tr>
	</tbody>
</table>

