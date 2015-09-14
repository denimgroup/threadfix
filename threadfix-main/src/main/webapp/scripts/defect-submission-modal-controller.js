var myAppModule = angular.module('threadfix');

myAppModule.controller('DefectSubmissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url, defectDefaultsConfig, timeoutService, tfEncoder) {

    $scope.focusInput = true;

    $scope.object = object;
    $scope.isDynamicForm = false;
    $scope.hasFields = true;

    $scope.config = config;
    $scope.defectDefaultsConfig = defectDefaultsConfig;

    $scope.initialized = false;
    $scope.vulns = config.vulns;

    $scope.showRemoveLink = $scope.vulns.length > 1;

    timeoutService.timeout();

    $scope.stdFormTemplateOptions = {};
    $scope.validModels = {};

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            $scope.initialized = true;
            timeoutService.cancel();

            if (data.success) {
                $scope.config = data.object.projectMetadata;
                $scope.config.typeName = data.object.defectTrackerName;

                // Only Bugzilla is not yet implemented Dynamic form
                if ($scope.config.typeName === 'HP Quality Center'
                    || $scope.config.typeName === 'JIRA'
                    || $scope.config.typeName === 'Jira'
                    || $scope.config.typeName === 'Version One'
                    || $scope.config.typeName === 'Microsoft TFS')
                    $scope.isDynamicForm = true;

                $scope.config.defectTrackerName = data.object.defectTrackerName;

                $scope.config.defects = data.object.defectList;

                if ($scope.config.defects && $scope.config.defects.length > 0) {
                    $scope.config.placeholder = $scope.config.defects[0];
                }

                if (!$scope.config.editableFields || !$scope.config.editableFields.length === 0) {
                    $scope.object.id = $scope.config.defects[0];
                    $scope.object.selectedComponent = $scope.config.components[0];
                    $scope.object.priority = $scope.config.priorities[0];
                    $scope.object.status = $scope.config.statuses[0];
                    $scope.object.version = $scope.config.versions[0];
                    $scope.object.severity = $scope.config.severities[0];
                } else {
                    createSubmitForm();
                    loadMainProfileDefaults();
                }
            } else {

                // setting these two booleans will hide the form.
                $scope.hasFields = false;
                $scope.isDynamicForm = true;

                $scope.errorMessage = data.message;
            }
        }).
        error(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.initialized = true;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });

    //load existing default profiles for this defectTracker
    var profilesUrl = tfEncoder.encode("/default/profiles/" + $scope.defectDefaultsConfig.defectTrackerId);
    $http.get(profilesUrl).
        success(function(data, status, headers, config){
            if (data.success) {
                $scope.defaultProfiles = data.object.defaultProfiles;
            }
            else {
                $scope.errorMessage = data.message;
            }
        }).
        error(function(data, status, headers, config) {
            $scope.errorMessage = "Couldn't load default profiles. HTTP status was " + status;
        });

    $scope.ok = function (form) {

        if (form.$valid) {
            timeoutService.timeout();
            $scope.loading = true;

            $scope.object.vulnerabilityIds = $scope.vulns.map(function(vuln) {
                return vuln.id;
            });

            for (var k in $scope.fieldsMap) {
                if (Object.prototype.toString.call($scope.fieldsMap[k]) === '[object Date]') {
                    $scope.stdFormTemplate.forEach(function(templateField){

                        // Date type for HPQC
                        if (k === templateField.model && templateField.placeholder === "yyyy-MM-dd") {
                            var d = $scope.fieldsMap[k];
                            //$scope.fieldsMap[k] = d.getFullYear() + "-" + d.getMonth()+1 + "-" + (d.getDate()+1);

                            var dd = d.getDate(); var mm = d.getMonth()+1; //January is 0!
                            var yyyy = d.getFullYear();
                            if(dd<10){dd='0'+dd}
                            if(mm<10){mm='0'+mm}
                            $scope.fieldsMap[k] = yyyy+'-'+mm+'-'+dd;


                        }
                    })
                }
            }

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

    var loadMainProfileDefaults = function() {
        if ($scope.defectDefaultsConfig.mainDefaultProfile){
            $scope.defectDefaultsConfig.selectedDefaultProfileId = $scope.defectDefaultsConfig.mainDefaultProfile.id;
            $scope.loadProfileDefaults();
        }
    };

    //here load default when different default is selected
    $scope.loadProfileDefaults = function(){
        if (!$scope.defectDefaultsConfig.selectedDefaultProfileId) return; //if select goes on first field which gives empty value
        var vulnerabilityIds = $scope.vulns.map(function(vuln) {
            return vuln.id;
        });
        var defaultsUrl = tfEncoder.encode("/default/" + $scope.defectDefaultsConfig.selectedDefaultProfileId + "/retrieve/" + vulnerabilityIds.join("-"));
        $scope.loadingProfileDefaults = true;

        $http.get(defaultsUrl)
            .success(function(data, status, headers, config){
                if (data.success) {
                    loadDefaultValues(data.object.defaultValues);
                }
                else {
                    $scope.errorMessage = data.message;
                }
                $scope.loadingProfileDefaults = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Couldn't load defaults. HTTP status was " + status;
                $scope.loadingProfileDefaults = false;
            });

    };

    var loadDefaultValues = function(defaultValues){
        for ( var fieldName in $scope.validModels) {
            // Set default values from selected profile
            if (fieldName in defaultValues){
                if (!(fieldName in $scope.stdFormTemplateOptions)){//check if its not a select field
                    $scope.fieldsMap[fieldName] = defaultValues[fieldName];
                }
                else if (defaultValues[fieldName] in $scope.stdFormTemplateOptions[fieldName]) { // check if select field accepts this default value
                    $scope.fieldsMap[fieldName] = defaultValues[fieldName];
                }

            } else { // For non-default fields, set to initial value, either blank or first item in required options
                if (!(fieldName in $scope.stdFormTemplateOptions) || !$scope.validModels[fieldName]){
                    $scope.fieldsMap[fieldName] = undefined;
                }
                else {
                    var scanned = false;
                    for (var firstItem in $scope.stdFormTemplateOptions[fieldName]) {
                        $scope.fieldsMap[fieldName] = firstItem;
                        scanned = true;
                        break;
                    }
                    if (!scanned)
                        $scope.fieldsMap[fieldName] = undefined;
                }
            }
        }
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
                "labelClass" : field.required ? "errors" : null,
                "options" : calculateOptions(field),
                "multiple" : field.supportsMultivalue,
                "val" : field.value
            };

            if (!field.required) {
                fieldForm.empty = "Select";
            }

            if (field.placeholder) {
                fieldForm.placeholder = field.placeholder;
            }

            if (field.validate) {
                fieldForm.validate = field.validate;
            }

            if (field.errorsMap) {
                fieldForm.errorsMap = field.errorsMap;
            }

            if (field.show) {
                fieldForm.show = field.show;
            }

            if (type === "select") {
                $scope.stdFormTemplateOptions[field.name]=fieldForm.options;
            }

            if (type === "text")
                fieldForm.maxLength = field.maxLength;

            if (type === "number") {
                if  (field.step)
                    fieldForm.step = field.step;
                if (field.minValue !== null)
                    fieldForm.minValue = field.minValue;
                if (field.maxValue !== null)
                    fieldForm.maxValue = field.maxValue;
            }

            if (field.editable === false) {
                fieldForm.readonly = true;
            }

            $scope.validModels[field.name] = field.required; // Save field is required or not for further usage
            $scope.stdFormTemplate.push(fieldForm)
        });

        if ($scope.config.editableFields.length === 1) {
            $scope.errorMessage = "ThreadFix was unable to populate a submission form. Check your configuration.";
            $scope.hasFields = false;
        }

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
                return "textarea";
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

            // Default the first element in dropdown list
            if (!$scope.fieldsMap[field.name] && field.required)
                $scope.fieldsMap[field.name] = key;

        }
        return options;
    };

    $scope.fieldsMap = {};
    $scope.requiredErrorMap = {}
});
