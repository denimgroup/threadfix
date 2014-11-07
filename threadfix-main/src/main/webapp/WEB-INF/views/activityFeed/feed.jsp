<div ng-controller="ActivityFeedController">
    <table class="table">
        <tr ng-repeat="activity in feed.activityList">
            <td>{{ activity.date | date }}</td>
            <td>{{ activity.activityType.name }}</td>
            <td>{{ activity.user.name }}</td>
            <td>{{ activity.details }}</td>
            <td><a ng-href="{{ encode(activity.linkPath) }}">{{ activity.linkText }}</a></td>
        </tr>
    </table>
</div>