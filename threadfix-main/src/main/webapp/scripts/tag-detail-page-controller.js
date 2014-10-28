var myAppModule = angular.module('threadfix')

myAppModule.controller('TagDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder) {

    $scope.tagId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.currentUrl = "/configuration/tags/" + $scope.tagId;
    $scope.$on('rootScopeInitialized', function() {
        $scope.loading = true;
        $http.get(tfEncoder.encode($scope.currentUrl + '/appList')).
            success(function(data, status, headers, config) {
                $scope.loading = false;
                if (data.success) {
                    $scope.appList = data.object.appList;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.loading = false;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    $scope.goToApp = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    }

    $scope.goToTeam = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id);
    }

});
