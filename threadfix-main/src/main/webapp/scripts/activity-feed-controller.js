var module = angular.module('threadfix');

module.controller('ActivityFeedController', function($scope, tfEncoder) {

    $scope.feed = undefined;

    $scope.$on('activityFeed', function($event, feed) {
        $scope.feed = feed;
    });

    $scope.encode = function(string) {
        return tfEncoder.encode(string);
    };

});