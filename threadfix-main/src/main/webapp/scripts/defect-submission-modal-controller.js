var myAppModule = angular.module('threadfix')

// TODO wrap this back into genericModalController and make config optional
myAppModule.controller('DefectSubmissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url, timeoutService) {

    $scope.focusInput = true;

    $scope.object = object;

    $scope.config = config;

    $scope.initialized = false;
    $scope.vulns = config.vulns;

    $scope.showRemoveLink = $scope.vulns.length > 1;

    timeoutService.timeout();

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            $scope.initialized = true;
            timeoutService.cancel();

            if (data.success) {
                $scope.config = data.object.projectMetadata;
                $scope.config.typeName = data.object.defectTrackerName;
                $scope.config.defectTrackerName = data.object.defectTrackerName;

                $scope.config.defects = data.object.defectList.map(function(defect) {
                    return defect.nativeId;
                });

                if (!$scope.config.editableFields || !$scope.config.editableFields.length === 0) {
                    $scope.object.id = $scope.config.defects[0];
                    $scope.object.selectedComponent = $scope.config.components[0];
                    $scope.object.priority = $scope.config.priorities[0];
                    $scope.object.status = $scope.config.statuses[0];
                    $scope.object.version = $scope.config.versions[0];
                    $scope.object.severity = $scope.config.severities[0];
                } else {
                    createSubmitForm();
                }
            } else {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }
        }).
        error(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.initialized = true;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });


    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            $scope.object.vulnerabilityIds = $scope.vulns.map(function(vuln) {
                return vuln.id;
            });

            $scope.object.fieldsMapStr = JSON.stringify($scope.fieldsMap);
            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;
                    $scope.errorMessage = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };

    $scope.remove = function(vuln) {
        var index = $scope.vulns.indexOf(vuln);

        if (index > -1) {
            $scope.vulns.splice(index, 1);
        }

        $scope.showRemoveLink = $scope.vulns.length > 1;
    };

    var createSubmitForm = function() {
        $scope.stdFormTemplate = [];
        $scope.config.editableFields.forEach(function(field) {

            var calType = calculateType(field.type);
            var label = field.required ? field.label + " *" : field.label;
            var labelClass = field.required ? "errors" : null;

            var fieldForm =  {
                "model" : field.name,
                "type" : calType,
                "label" : label,
                "required" : field.required,
                "labelClass" : labelClass
            };
            if (calType === "select") {
                fieldForm.empty = "Select";
                fieldForm.options = calculateOptions(field);
                fieldForm.multiple = field.supportsMultivalue;

            };
            $scope.stdFormTemplate.push(fieldForm)
        });
    };

    var calculateType = function (oldType) {

        var lowerCaseOldType = oldType.toLowerCase();

        if (lowerCaseOldType === "userslist" || lowerCaseOldType === "lookuplist" || lowerCaseOldType === "reference")
            return "select";
        else if (lowerCaseOldType === "string")
            return "text";
        else if (lowerCaseOldType === "memo")
            return "textarea"
        else if (lowerCaseOldType === "float")
            return "number";
        else
            return lowerCaseOldType;

    };

    var calculateOptions = function (field) {
        var options = new Object();

        for (var key in field.optionsMap) {
            var value = {
                "label" : field.optionsMap[key]
            };
            options[key] = value;
        };
        return options;
    };

    $scope.fieldsMap = {};

});
