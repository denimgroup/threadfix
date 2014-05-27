var myAppModule = angular.module('threadfix')


// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);

// TODO wrap this back into genericModalController and make config optional

myAppModule.controller('PermissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, headerText) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.loading = false;

    $scope.headerText = headerText;

    var buildMap = function(object) {

        var returnObject = {};

        returnObject.roleIdMapList = [];
        returnObject.applicationIds = [];

        if (object.role) {
            returnObject.roleId = object.role.id;
        }

        returnObject.teamId = object.team.id;
        //returnObject.userId = object.user.id;
        returnObject.allApps = object.allApps;

        $scope.config.appList.forEach(function(app) {

            if (app.role && app.role.id !== 0) {
                returnObject.applicationIds.push(app.id);

                returnObject.roleIdMapList.push(String(app.id) + "-" + String(app.role.id))
            }
        });

        return returnObject;
    };

    $scope.ok = function (valid) {

        if (valid) {

            var returnValue = buildMap($scope.object);

            $scope.loading = true;

            threadFixModalService.post(url, returnValue).
                success(function(data, status, headers, config) {
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {

                                    if (data.errorMap[index] === 'errors.self.certificate') {
                                        $scope.showKeytoolLink = true;
                                    } else {
                                        $scope.object[index + "_error"] = data.errorMap[index];
                                    }
                                }
                            }
                        } else {
                            $scope.error = "Failure. Message was : " + data.message;
                        }
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.setApps = function(apps) {
        $scope.config.appList = apps;

        $scope.config.appList.forEach(function (app) {
            app.role = { id: 0 };
        });

    }

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    }

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };

    $scope.showDeleteDialog = function(itemName) {
        if (confirm("Are you sure you want to delete this " + itemName + "?")) {
            $http.post(deleteUrl).
                success(function(data, status, headers, config) {
                    $modalInstance.close(false);
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

});
