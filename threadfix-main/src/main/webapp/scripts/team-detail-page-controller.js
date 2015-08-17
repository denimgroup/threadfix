var myAppModule = angular.module('threadfix')

myAppModule.controller('TeamDetailPageController', function ($scope, $window, $http, $modal, $log, $rootScope, tfEncoder, $timeout, appUsageService) {

    $scope.rightReportTitle = "Top 10 Vulnerable Applications";
    $scope.empty = false;

    $scope.onFileSelect = function($files) {
        $scope.$broadcast('fileDragged', $files);
    };

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.teamId  = $window.location.pathname.match(/([0-9]+)$/)[0];

    $scope.showAppLimitMessage = function(number) {
        if (number != -1)
            alert('You have reached the application limit of ' + number + ' for your current license. To upgrade your license, please contact Denim Group.');
        else
            alert('It appears that your license file is not valid, the operation is currently not available. Please contact Denim Group.');
    };

    $scope.clickVulnTab = function() {
        $rootScope.$broadcast('loadVulnerabilitySearchTable');
    };

    var countVulnerabilities = function() {
        $scope.vulnerabilityCount = 0;
        $scope.applications.forEach(function(application) {
            $scope.vulnerabilityCount += application.totalVulnCount;
        });
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = "&orgId=" + $scope.teamId;
        $http.get(tfEncoder.encodeRelative($scope.teamId + "/info")).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.team = data.object.team;
                    $scope.team.applications = data.object.applications;
                    $scope.applications = data.object.applications;
                    $scope.users = data.object.users;
                    countVulnerabilities();
                    $scope.$broadcast('team', $scope.team);
                    $scope.$broadcast('seeMoreExtension', "/" + $scope.team.id);
                } else {
                    var error = "Error encountered. Message was " + $scope.message;
                    $scope.errorMessage = error;
                    $log.error(error);
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Encountered error. HTTP status was " + status;
                $log.error("Encountered error. HTTP status was " + status);
            });
    });

    $scope.openEditModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'editTeamModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/edit");
                },
                object: function () {
                    var teamCopy = angular.copy($scope.team);
                    return teamCopy;
                },
                buttonText: function() {
                    return "Save Changes";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedTeam) {
            if (editedTeam) {
                $scope.team = editedTeam;
                $scope.successMessage = "Successfully edited team " + editedTeam.name;
            } else {
                $window.location.href = tfEncoder.encode("/teams");
            }
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openAppModal = function() {

        var application = {
            team: {
                id: $scope.team.id,
                name: $scope.team.name
            },
            applicationCriticality: {
                id: 2
            },
            frameworkType: 'DETECT'
        };

        var modalInstance = $modal.open({
            templateUrl: 'newApplicationModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/organizations/" + $scope.team.id + "/modalAddApp");
                },
                object: function () {
                    return application;
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return "Add Application";
                }
            }
        });

        modalInstance.result.then(function (object) {
            if (!$scope.applications || $scope.applications.length === 0) {
                $scope.applications = [];
            }
            $scope.applications.push(object.application);

            $scope.applications.sort(nameCompare);

            $scope.successMessage = appUsageService.getUsage(object);

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToPage = function(app) {
        $window.location.href = tfEncoder.encodeRelative($scope.team.id + "/applications/" + app.id);
    };

    $scope.showUsers = function() {
        $modal.open({
            templateUrl: 'permissibleUsersModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return {};
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return {};
                }
            }
        });
    };

});