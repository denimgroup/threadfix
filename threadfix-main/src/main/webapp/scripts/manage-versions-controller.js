var myAppModule = angular.module('threadfix');

myAppModule.controller('ManageVersionsController', function ($modal, $log, $scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, tfEncoder, threadFixModalService) {

    $scope.object = object;

    $scope.config = config;

    $scope.focusInput = true;

    var dateCompare = function(a,b) {
        return a.date- b.date;
    };

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name, $scope.object);
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };

    $scope.editVersion = function(oldVersion) {
        var modalInstance = $modal.open({
            templateUrl: 'newVersionForm.html',
            windowClass: 'wide',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/organizations/" + $scope.config.application.team.id + "/applications/"
                    + $scope.config.application.id + "/version/" + oldVersion.id + "/edit");
                },
                object: function () {
                    return angular.copy(oldVersion);
                },
                config: function() {
                    return {title: "Edit Version " + oldVersion.name};
                },
                buttonText: function() {
                    return "Submit Version";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/organizations/" + $scope.config.application.team.id + "/applications/"
                    + $scope.config.application.id + "/version/" + oldVersion.id + "/delete");
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (newVersion) {

            if (newVersion) {
                threadFixModalService.deleteElement($scope.config.versions, oldVersion);
                threadFixModalService.addElement($scope.config.versions, newVersion);

                $scope.successMessage = "Version " + newVersion.name + " has been edited.";
                $scope.config.versions.sort(dateCompare);
            } else {
                threadFixModalService.deleteElement($scope.config.versions, oldVersion);
                $scope.successMessage = "Version " + oldVersion.name + " has been deleted.";
            }
            $rootScope.$broadcast('versionsChange', $scope.config.versions);

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.newVersion = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newVersionForm.html',
            windowClass: 'wide',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/organizations/" + $scope.config.application.team.id + "/applications/" + $scope.config.application.id + "/version/new");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {title: "New Version"};
                },
                buttonText: function() {
                    return "Submit Version";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (newVersion) {
            $scope.successMessage = "Version " + newVersion.name + " has been added.";

            threadFixModalService.addElement($scope.config.versions, newVersion);
            $scope.config.versions.sort(dateCompare);
            $rootScope.$broadcast('versionsChange', $scope.config.versions);

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

});
