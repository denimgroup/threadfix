var myAppModule = angular.module('threadfix')

// TODO wrap this back into genericModalController and make config optional
myAppModule.controller('DefectSubmissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url, timeoutService) {

    $scope.focusInput = true;

    $scope.object = object;
    $scope.isDynamicForm = false;

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
                if ($scope.config.typeName === 'HP Quality Center'
                    || $scope.config.typeName === 'Jira'
                    || $scope.config.typeName === 'Version One')
                    $scope.isDynamicForm = true;
                $scope.config.defectTrackerName = data.object.defectTrackerName;

                $scope.config.defects = data.object.defectList.map(function(defect) {
                    return defect.nativeId;
                });
                $scope.config.defects = data.object.defectList;

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


    $scope.ok = function (form) {

        if (form.$valid) {
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

    $scope.emptyMultiChoice = function(path) {
        var field = $scope.fieldsMap[path];

        if (field.length === 1 && field[0] === "") {
            delete $scope.fieldsMap[path];
        }
    };

    $scope.checkAndReset = function(pathSegment1, pathSegment2) {
        if (!$scope.fieldsMap[pathSegment1][pathSegment2]) {
            delete $scope.fieldsMap[pathSegment1][pathSegment2];
        }

        $scope.requiredErrorMap[pathSegment1] = Object.keys($scope.fieldsMap[pathSegment1]).length === 0;
    };

    var createSubmitForm = function() {
        $scope.stdFormTemplate = [];
        $scope.config.editableFields.forEach(function(field) {
            var type = calculateType(field.type);

            var fieldForm =  {
                "model" : field.name,
                "type" : type,
                "label" : field.required ? field.label + " *" : field.label,
                "required" : field.required,
                "empty" : "Select",
                "labelClass" : field.required ? "errors" : null,
                "options" : calculateOptions(field),
                "multiple" : field.supportsMultivalue
            };

            if (field.placeholder) {
                fieldForm.placeholder = field.placeholder;
            }

            if (field.validate) {
                fieldForm.validate = field.validate;
            }

            if (field.errorsMap) {
                fieldForm.errorsMap = field.errorsMap;
            }

            if (type === "text")
                fieldForm.maxLength = field.maxLength;
            $scope.stdFormTemplate.push(fieldForm)
        });
    };

    /**
     * This is to customize type names used in Defect Tracker system to supported type in Dynamic form angular
     * @param oldType
     * @returns {string}
     */
    var calculateType = function (oldType) {

        if (oldType) {
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
        }

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
    $scope.requiredErrorMap = {}
});
