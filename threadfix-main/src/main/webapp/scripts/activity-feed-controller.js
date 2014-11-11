var module = angular.module('threadfix');

module.controller('ActivityFeedController', function($scope, tfEncoder) {

    $scope.feed = undefined;

    var replace = function(string, target, newValue) {
        var index = string.indexOf(target);

        return string.substring(0, index) + newValue + string.substring(index + target.length);
    };

    var process = function(feed) {
        feed.activityList.forEach(function(activity) {
            var formatString = activity.activityType.formatString;

            formatString = replace(formatString, '{user}', activity.user.name);
            formatString = replace(formatString, '{details}', activity.details);

            var linkIndex = formatString.indexOf('{link}');
            var linkIndexEnd = linkIndex + 6;
            activity.beforeLink = formatString.substring(0, linkIndex);
            activity.afterLink = formatString.substring(linkIndexEnd);
        });

        return feed;
    };

    $scope.$on('activityFeed', function($event, feed) {
        $scope.feed = process(feed);
    });

    $scope.encode = function(string) {
        return tfEncoder.encode(string);
    };

});