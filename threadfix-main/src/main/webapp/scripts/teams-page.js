var myAppModule = angular.module('threadfix', ['ui.bootstrap']).
    factory('threadfixAPIService', function($http) {

        var apiKey = "xZ32iTkKAVVBUio2cR81mgqpLRw19EMAvxmkLHvkM";

        var threadfixAPIService = {};

        threadfixAPIService.getTeams = function() {
            return $http({
                method: 'GET',
                url: '/rest/teams?apiKey=' + apiKey
            });
        };

        return threadfixAPIService;
    });

myAppModule.controller('NewApplicationModalController', function ($scope, $modalInstance, team) {

    $scope.application = {
        team: team,
        applicationCriticality: {
            id: 1
        },
        frameworkType: {
            id: 1
        }
    };

    $scope.ok = function () {
        $modalInstance.close($scope.application);
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});


myAppModule.controller('ApplicationsIndexController', function($scope, $log, $modal, threadfixAPIService) {

    $scope.progressText = 'Loading...';

    threadfixAPIService.getTeams().
        success(function(data, status, headers, config) {
            $scope.progressText = 'Got stuff.';

            if (data.success) {
                $scope.teams = data.object;
            } else {
                $scope.output = "Failure. Message was : " + data.message;
            }
        }).
        error(function(data, status, headers, config) {
            $scope.progressText = "Failure. HTTP status was " + status;
        });

    $scope.toggle = function(team) {

        if (typeof team.expanded === "undefined") {
            team.expanded = false;
        }

        if (team.expanded) {
            team.expanded = false;
        } else {
            team.expanded = true;
        }
    }

    $scope.openAppModal = function (team) {

        var modalInstance = $modal.open({
            templateUrl: 'newApplicationModal.html',
            controller: 'NewApplicationModalController',
            resolve: {
                team: function () {
                    return team;
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            // TODO add REST call to create an application. We need REST-enabled endpoints.
            $scope.lastApplication = newApplication;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

});
