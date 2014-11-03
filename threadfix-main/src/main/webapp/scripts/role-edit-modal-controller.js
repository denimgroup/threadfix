var myAppModule = angular.module('threadfix')


// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);

// TODO wrap this back into genericModalController and make config optional

myAppModule.controller('RoleEditModalController',
    function ($scope, $rootScope, $modalInstance, tfEncoder, $http,
              threadFixModalService, object, config, url, buttonText, deleteUrl) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            $scope.loading = true;

            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {
                                    $scope.object[index + "_error"] = data.errorMap[index];
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

    $scope.setAll = function(value) {
        $scope.object.canGenerateReports = value;
        $scope.object.canGenerateWafRules = value;
        $scope.object.canManageApiKeys = value;
        $scope.object.canManageApplications = value;
        $scope.object.canManageGrcTools = value;
        $scope.object.canManageDefectTrackers = value;
        $scope.object.canManageRemoteProviders = value;
        $scope.object.canManageRoles = value;
        $scope.object.canManageScanAgents = value;
        $scope.object.canManageSystemSettings = value;
        $scope.object.canManageTeams = value;
        $scope.object.canManageTags = value;
        $scope.object.canViewErrorLogs = value;
        $scope.object.canUploadScans = value;
        $scope.object.canSubmitDefects = value;
        $scope.object.canModifyVulnerabilities = value;
        $scope.object.canManageWafs = value;
        $scope.object.canManageVulnFilters = value;
        $scope.object.canManageUsers = value;
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };

    $scope.showDeleteDialog = function(role) {

        if (role.canDelete) {
            if (confirm("Are you sure you want to delete this role?")) {
                $http.post(deleteUrl).
                    success(function(data, status, headers, config) {

                        if (data.success && data.object.indexOf("invalidate") != -1) {
                            alert("You have deleted a role that was part of your account. Please log back in.");
                            window.location.href = tfEncoder.encode("/spring_security_logout");
                        } else {
                            $modalInstance.close(false);
                        }
                    }).
                    error(function(data, status, headers, config) {
                        $scope.error = "Failure. HTTP status was " + status;
                    });
            }
        } else {
            alert("You cannot delete this role because doing so would make some ThreadFix administrative functions unavailable.")
        }
    };

});
