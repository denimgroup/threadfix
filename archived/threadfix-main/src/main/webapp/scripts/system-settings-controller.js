var myAppModule = angular.module('threadfix');

myAppModule.controller('SystemSettingsController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder, threadFixModalService) {

    var prevFileUploadLocation;

    $scope.$on('rootScopeInitialized', function() {
        var url = tfEncoder.encode('/configuration/settings/objects');
        $http.get(url).
            success(function(data) {

                if (data.success) {
                    $scope.object = data.object.defaultConfiguration;
                    $scope.roleList = data.object.roleList;
                    $scope.applicationCount = data.object.applicationCount;
                    $scope.licenseCount = data.object.licenseCount;
                    $scope.licenseExpirationDate = data.object.licenseExpirationDate;
                    $scope.dashboardReports = data.object.dashboardReports;
                    $scope.applicationReports = data.object.applicationReports;
                    $scope.teamReports = data.object.teamReports;
                    $scope.exportFieldDisplayNames = data.object.exportFieldDisplayNames;
                    $scope.exportFields = data.object.exportFields;

                    $scope.canImportLDAPGroups = data.object.canImportLDAPGroups;

                    prevFileUploadLocation = $scope.object.fileUploadLocation;

                    $scope.roleList.unshift({id: 0, displayName: "Read Access"});

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve LDAP settings. HTTP status was " + status;
            });
    });

    $scope.shouldDisable = function() {
        var returnValue = true;

        if ($scope.object) {
            returnValue = !($scope.object.activeDirectoryBase &&
            $scope.object.activeDirectoryUsername &&
            $scope.object.activeDirectoryCredentials &&
            $scope.object.activeDirectoryURL);
        }

        return returnValue;
    };

    $scope.selectedRole = function(roleId) {
        return $scope.object.defaultRoleId == roleId;
    };

    $scope.populateWithUserBaseUrl = function() {
        var url = tfEncoder.encode('/configuration/settings/currentlyUsedBaseUrl');
        $http.get(url)
            .success(function(data) {
                if (data.success) {
                    $scope.object.baseUrl = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            })
            .error(function(data, status) {
                $scope.errorMessage = "Failed to get currently used base URL. HTTP status was " + status;
            });
    };

    $scope.submit = function (valid) {
        var url = tfEncoder.encode('/configuration/settings');

        if (valid) {
            $scope.loading = true;

            if (prevFileUploadLocation !== '' && $scope.object.fileUploadLocation === '') {
                $scope.object.deleteUploadedFiles = confirm("You've cleared the File Upload Location field. " +
                "Would you like to delete the files residing in that directory?");
            }

            $http.post(url, $scope.object).
                success(function(data) {
                    $scope.loading = false;

                    if (data.success) {
                        $scope.successMessage = "Configuration was saved successfully.";
                        $scope.errorMessage = null;
                            $scope.object = data.object;
                        prevFileUploadLocation = $scope.object.fileUploadLocation;
                        window.scrollTo(0, 0);
                    } else {
                        $scope.errorMessage = "Failure: " + data.message;
                        $scope.successMessage = null;

                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {
                                    $scope.object[index + "_error"] = data.errorMap[index];
                                }
                            }
                        }
                    }
                }).
                error(function(data, status) {
                    $scope.loading = false;
                    $scope.errorMessage = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.ok = function (valid) {
        var url = tfEncoder.encode('/configuration/settings/checkLDAP');

        if (valid) {
            $scope.loading = true;

            $http.post(url, $scope.object).
                success(function(data) {
                    $scope.loading = false;

                    if (data.success) {
                        $scope.LDAPSuccessMessage = data.object;
                    } else {
                        $scope.error = "Failure: " + data.message;
                        $scope.LDAPError = "Failure: " + data.message;
                    }
                }).
                error(function(data, status) {
                    $scope.loading = false;
                    if (data && data.message) {
                        $scope.error = "Failure: " + data.message;
                        $scope.LDAPError = "Failure: " + data.message;
                    } else {
                        $scope.error = "Failure. HTTP status was " + status;
                        $scope.LDAPError = "Failure. HTTP status was " + status;
                    }
                });
        }
    };

    $scope.sortableOptions = {
        placeholder: "exportField",
        connectWith: ".export-fields-container"
    };
});