<table class="table">
	<thead>
		<tr>
			<th class="first"></th>
			<th>User</th>
			<th>Date</th>
			<th class="last">Comment</th>
		<tr>
	</thead>
	<tbody>
        <tr ng-hide="vuln.vulnerabilityComments" class="bodyRow">
            <td colspan="4" style="text-align:center;">No comments found.</td>
        </tr>
        <tr ng-show="vuln.vulnerabilityComments" ng-repeat="comment in vuln.vulnerabilityComments" class="bodyRow left-align">
            <td id="commentNum{{ $index }}">{{ $index + 1 }}</td>
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

