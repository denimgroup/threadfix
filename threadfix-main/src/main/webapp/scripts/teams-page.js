var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationsIndexController', function($scope, $log, $modal, threadfixAPIService) {

    $scope.progressText = 'Loading...';

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

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
                },
                csrfToken: function() {
                    return $scope.csrfToken;
                }
            }
        });

        modalInstance.result.then(function (newApplication) {
            team.applications.push(newApplication);

            team.applications.sort(nameCompare);

            team.expanded = true;
            loadGraph(team);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.expand = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = true;
            loadGraph(team);
        });
    }

    $scope.contract = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = false;
        });
    }

    var loadGraph = function(team) {

        if (team.report == null) {

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
    }

    $scope.openTeamModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTeamModal.html',
            controller: 'NewTeamModalController',
            resolve: {
                csrfToken: function() {
                    return $scope.csrfToken;
                }
            }
        });

        modalInstance.result.then(function (newTeam) {
            $scope.teams.push(newTeam);

            $scope.teams.sort(nameCompare);

            $scope.successMessage = "Successfully added team " + newTeam.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});
