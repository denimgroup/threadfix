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

        threadfixAPIService.loadReport = function(team) {
            return $http({
                method: 'GET',
                url: team.graphUrl
            });
        };

        return threadfixAPIService;
    });


// For image tags and stuff
myAppModule.directive('bindHtmlUnsafe', function( $compile ) {
    return function( $scope, $element, $attrs ) {

        var compile = function( newHTML ) { // Create re-useable compile function

            newHTML = $compile(newHTML)($scope); // Compile html
            $element.html('').append(newHTML);
        };

        var htmlName = $attrs.bindHtmlUnsafe; // Get the name of the variable
        // Where the HTML is stored

        $scope.$watch(htmlName, function( newHTML ) { // Watch for changes to
            // the HTML
            if(!newHTML) return;
            compile(newHTML);   // Compile it
        });

    };
});

myAppModule.controller('NewApplicationModalController', function ($scope, $modalInstance, team) {

    $scope.application = {
        team: {
            id: team.id,
            name: team.name
        },
        url: 'http://',
        applicationCriticality: {
            id: 2
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

        loadGraph(team);
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

    var loadGraph = function(team) {

        var failureDiv = '<div class="" style="margin-top:10px;margin-right:20px;width:300px;height:200px;text-align:center;line-height:150px;">Failed to load report.</div>';

        threadfixAPIService.loadReport(team).
            success(function(data, status, headers, config) {

                // TODO figure out Jasper better, it's a terrible way to access the report images.
                var matches = data.match(/(<img src="\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                if (matches !== null && matches[1] !== null) {
                    team.report = matches[1];
                } else {
                    team.report = failureDiv;
                }
            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                team.report = failureDiv;
            });
    }

});
