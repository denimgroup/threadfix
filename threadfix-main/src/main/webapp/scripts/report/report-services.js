var threadfixModule = angular.module('threadfix');

threadfixModule.factory('reportExporter', function($log, d3, $http, tfEncoder, vulnSearchParameterService, vulnTreeTransformer, $timeout) {

    var reportExporter = {};
    var browerErrMsg = "Sorry, your browser does not support this feature. Please upgrade IE version or change to Chrome which is recommended.";

    reportExporter.exportScan = function(data, contentType, fileName) {

        $timeout(function() {
            var blob = new Blob([data], { type: contentType });

            // IE <10, FileSaver.js is explicitly unsupported
            if (checkOldIE()) {
                var success = false;
                if (document.execCommand) {
                    var oWin = window.open("about:blank", "_blank");
            //        oWin.document.open("application/csv", "replace");
                    oWin.document.charset = "utf-8";
                    oWin.document.write('sep=,\r\n' + data);
                    oWin.document.close();
                    success = oWin.document.execCommand('SaveAs', true, fileName);
                    oWin.close();
                }

                if (!success)
                    alert(browerErrMsg);
                return;
            }

            // Else, using saveAs of FileSaver.js
            saveAs(blob, fileName);
        }, 200);
    };

    reportExporter.exportCSV = function(data, contentType, fileName) {

        $timeout(function() {
            var blob = new Blob([data], { type: contentType });

            // IE <10, FileSaver.js is explicitly unsupported
            if (checkOldIE()) {
                var success = false;
                if (document.execCommand) {
                    var oWin = window.open("about:blank", "_blank");
                    oWin.document.open("application/csv", "replace");
                    oWin.document.charset = "utf-8";
                    oWin.document.write('sep=,\r\n' + data);
                    oWin.document.close();
                    success = oWin.document.execCommand('SaveAs', true, fileName);
                    oWin.close();
                }

                if (!success)
                    alert(browerErrMsg);
                return;
            }

            // Else, using saveAs of FileSaver.js
            saveAs(blob, fileName);
        }, 200);
    };

    reportExporter.exportPDF = function(d3, exportInfo, width, height, name) {
        reportExporter.exportPDFSvg(d3, selectSvg(exportInfo.svgId), width, height, name, exportInfo.isPDF);
    };

    var checkOldIE = function() {
        // IE <10, unsupported
         return (typeof navigator !== "undefined" &&
            /MSIE [1-9]\./.test(navigator.userAgent));
    };

    reportExporter.checkOldIE = checkOldIE;

    var selectSvg = function(svgId) {
        var svg = d3.select("svg");
        d3.selectAll("svg").each(function(d, i) {

            if (d3.select(this).attr("id") === svgId)
                svg = d3.select(this);

            $log.info(d3.select(this).attr("id"));
        });
        return svg;
    };

    reportExporter.exportPDFSvg = function(d3, svg, width, height, name, isPDF) {
        var node = svg
            .attr("version", 1.1)
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .node();

        styles(node);

        var html = node.parentNode.innerHTML;

        var imgsrc = 'data:image/svg+xml;base64,'+ btoa(html);
        var img = '<img src="'+imgsrc+'">';
        d3.select("#svgdataurl").html(img);

        var canvas = document.createElement("canvas");
        canvas.width = (svg.attr("width")) ? svg.attr("width") : width;
        canvas.height = (svg.attr("height")) ? svg.attr("height") : height;
        var context = canvas.getContext("2d");

        var image = new Image();
        image.src = imgsrc;
        image.onload = function() {
            context.drawImage(image, 0, 0);

            var canvasdata = canvas.toDataURL("image/png");

            if (isPDF) {
                var pdf = new jsPDF();
                pdf.addImage(canvasdata, 'PNG', 10, 10);

                //Adding table
                pdf.cellInitialize();
                pdf.setFontSize(10);

                var table = d3.select('#vulnListDiv table')[0][0];
                for (var i=0; i<table.rows.length; i++) {
                    var tableRow = table.rows[i];
                    for (var j=0; j<tableRow.cells.length; j++) {
                        pdf.cell(10, 50, 40, 30, tableRow.cells[j].innerText || tableRow.cells[j].textContent, i);
                        console.log(tableRow.cells[j].innerText || tableRow.cells[j].textContent);
                        pdf.cellAddPage();
                    }
                }
                pdf.save(name + ".pdf");
            } else {
                var pngimg = '<img src="'+canvasdata+'">';
                d3.select("#pngdataurl").html(pngimg);

                var a = document.createElement("a");
                a.download = name + ".png";
                a.href = canvasdata;
                a.click();
            }
        };

    };

    reportExporter.exportPDFTable = function($scope, parameters, exportInfo) {

        if (checkOldIE()) {
            alert(browerErrMsg);
            return;
        }

        $scope.exportingPDF = true;

        //Retrieving table data
        vulnSearchParameterService.updateParameters($scope, parameters);
        var isDISASTIG = parameters.isDISASTIG;

        $http.post(tfEncoder.encode("/reports/search/export/pdf"), parameters).
            success(function(data, status, headers, config) {
                if (data.success) {
                    var exportList = [];
                    data.object.forEach(function(elementObj){
                        var element = elementObj.element;
                        var info = elementObj.info;
                        element.vulns = info.vulns;
                        element.vulnCount = info.vulnCount;
                        exportList.push(element);
                    });
                    $scope.exportVulnTree = vulnTreeTransformer.transform(exportList, parameters.owasp, isDISASTIG ? $scope.DISA_STIG : undefined);
                    //$scope.$apply();

                    reportExporter.exportPDFTableFromId($scope, exportInfo, null, function() {
                        $scope.exportingPDF = false;
                        $scope.exportVulnTree = null;
                    });

                } else if (data.message) {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                    $scope.exportingPDF = false;
                }

            }).
            error(function(data, status, headers, config) {
                $log.info("Got " + status + " back.");
                $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
                $scope.exportingPDF = false;
            });

    };

    reportExporter.exportPDFTableFromId = function($scope, exportIds, tableData, cleanup) {

        if (checkOldIE()) {
            alert(browerErrMsg);
            return;
        }

        var fileName = getName(exportIds);
        var tableId = exportIds.tableId, graghId = exportIds.svgId;

        var pdf = new jsPDF({lineHeight: 0.85});
        addSvgToPdf($scope, pdf, graghId, function() {

            // Adding summary table in Compliance report
            if (tableData && tableData.length > 0) {
                pdf.cellInitialize();
                pdf.setFontSize(10);
                var headers = Object.keys(tableData[0]);
                headers.forEach(function(header){
                    pdf.cell(20, 150, 50, 10, header, 0);
                });
                tableData.forEach(function(row, i){
                    headers.forEach(function(header){
                        pdf.cell(20, 150, 50, 10, "" + row[header], i+1);
                    });
                });
            }

            if (graghId && tableId)
                pdf.addPage();
            addElementToPdf(pdf, tableId);
            pdf.save(fileName + '.pdf');
            if (cleanup) {
                cleanup();
            }
        });

    };

    var addSvgToPdf = function($scope, pdf, graphId, continueBuildingPdf) {

        if (graphId) {
            var svg = selectSvg(graphId);
            var node = svg
                .attr("version", 1.1)
                .attr("xmlns", "http://www.w3.org/2000/svg")
                .node();

            styles(node);

            var html = node.parentNode.innerHTML;

            var imgsrc = 'data:image/svg+xml;base64,' + btoa(html);
            var img = '<img src="' + imgsrc + '">';
            d3.select("#svgdataurl").html(img);

            var image = new Image();
            image.onload = function() {
                $scope.$apply(function() {
                    var canvas = null;
                    var context = null;
                    var canvasdata = null;
                    try {
                        canvas = document.createElement("canvas");
                        canvas.width = svg.attr("width");
                        canvas.height = svg.attr("height");

                        context = canvas.getContext("2d");
                        context.drawImage(image, 0, 0);
                        canvasdata = canvas.toDataURL("image/png");
                        pdf.addImage(canvasdata, 'PNG', 10, 10);

                    } catch (ex) {
                        // So I guess, you are using IE...
                        $log.warn(ex);
                        try {
                            canvas = document.createElement("canvas");
                            canvas.width = svg.attr("width");
                            canvas.height = svg.attr("height");

                            canvg(canvas, html);
                            var canvasData = canvas.toDataURL("image/jpeg");
                            pdf.addImage(canvasData, 'JPEG', 10, 10);
                        } catch (ex1) {
                            $log.warn(ex1);
                            if (checkOldIE())
                                alert(browerErrMsg);
                        }
                    }
                    continueBuildingPdf();
                });
            };
            image.src = imgsrc;
        } else {
            $timeout(continueBuildingPdf, 200);
        }
    };

    var addElementToPdf = function(pdf, elementId) {
        if (elementId) {
            pdf.cellInitialize();
            pdf.setFontSize(10);
            var specialElementHandlers = {
                '#editor': function (element, renderer) {
                    return true;
                }
            };

            var table = d3.select("#" + elementId)[0][0];
            pdf.fromHTML(table, 15, 15, {
                'width': 180,
                'elementHandlers': specialElementHandlers
            });
        }

        return pdf;
    };

    var getName = function(exportInfo) {
        var teamsName = (exportInfo && exportInfo.teams) ? "_" + exportInfo.teams : "",
            appsName = (exportInfo && exportInfo.apps) ? "_" + exportInfo.apps : "",
            tagsName = (exportInfo && exportInfo.tags) ? "_" + exportInfo.tags : "",
            title = (exportInfo && exportInfo.title) ? exportInfo.title : "Report";
        return title + teamsName + appsName + tagsName;
    };

    var styles = function(dom) {
        var used = "";
        var sheets = document.styleSheets;
        for (var i = 0; i < sheets.length; i++) {
            var rules = sheets[i].cssRules;
            for (var j = 0; j < rules.length; j++) {
                var rule = rules[j];
                if (typeof(rule.style) != "undefined") {
                    try {
                        var elems = dom.querySelectorAll(rule.selectorText);
                        if (elems.length > 0) {
                            used += rule.selectorText + " { " + rule.style.cssText + " }\n";
                        }
                    } catch (x) {
                        $log.warn(x);
                    }
                }
            }
        }

        var s = document.createElement('style');
        s.setAttribute('type', 'text/css');
        s.innerHTML = "<![CDATA[\n" + used + "\n]]>";

        var defs = document.createElement('defs');
        defs.appendChild(s);
        dom.insertBefore(defs, dom.firstChild);
    };

    return reportExporter;
});

threadfixModule.factory('d3Service', function() {

    var d3Service = {};

    d3Service.getColorScale = function(d3, range) {
        return d3.scale.ordinal()
            .range(range);
    };

    d3Service.getScaleOrdinalRangeBand = function(d3, range, scale) {
        return d3.scale.ordinal()
            .rangeRoundBands(range, scale);
    };

    d3Service.getScaleLinearRange = function(d3, range) {
        return d3.scale.linear()
            .rangeRound(range);
    };

    d3Service.getAxis = function(d3, scale, orient) {
        return  d3.svg.axis()
            .scale(scale)
            .tickSize(3)
            .orient(orient);
    };

    d3Service.getAxisFormat = function(d3, scale, orient, format) {
        return  d3Service.getAxis(d3, scale, orient)
            .tickFormat(format);
    };

    d3Service.getSvg = function(d3, elementId, w, h) {
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    };

    d3Service.getExistingSvg = function(d3, elementId, w, h) {
        var svgs = d3.select(elementId).selectAll("svg");
        if (svgs.length>0 && svgs[0].length>0)
            return svgs;
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    };

    d3Service.getTip = function(d3, clazz, offset, tipId) {
        return d3.tip()
            .attr('class', clazz)
            .attr('id', tipId)
            .offset(offset);
    };

    return d3Service;

});

threadfixModule.factory('reportConstants', function(customSeverityService) {

    var reportConstants = {};

    reportConstants.vulnTypeColorList = ["#014B6E", "#458A37", "#EFD20A", "#F27421", "#F7280C", "#C2A677",
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd" ];
    reportConstants.vulnTypeTextColorList = ["#688c9d", "#458A37", "#EFD20A", "#F27421", "#F7280C", "#C2A677",
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd" ];
    reportConstants.vulnTypeList = ["Info", "Low", "Medium", "High", "Critical"];

    customSeverityService.addCallback(function() {
        reportConstants.vulnTypeList = [
            customSeverityService.getCustomSeverity("Info"),
            customSeverityService.getCustomSeverity("Low"),
            customSeverityService.getCustomSeverity("Medium"),
            customSeverityService.getCustomSeverity("High"),
            customSeverityService.getCustomSeverity("Critical")
        ];

        reportConstants.vulnTypeColorMap = {
            Old: {
                graphColor: reportConstants.vulnTypeColorList[5],
                textColor: reportConstants.vulnTypeTextColorList[5]
            },
            Closed: {
                graphColor: reportConstants.vulnTypeColorList[6],
                textColor: reportConstants.vulnTypeTextColorList[6]
            },
            Resurfaced: {
                graphColor: reportConstants.vulnTypeColorList[7],
                textColor: reportConstants.vulnTypeTextColorList[7]
            },
            New: {
                graphColor: reportConstants.vulnTypeColorList[8],
                textColor: reportConstants.vulnTypeTextColorList[8]
            },
            Total: {
                graphColor: reportConstants.vulnTypeColorList[9],
                textColor: reportConstants.vulnTypeTextColorList[9]
            }

        };

        reportConstants.vulnTypeColorMap[customSeverityService.getCustomSeverity('Info')] = {
            graphColor: reportConstants.vulnTypeColorList[0],
            textColor: reportConstants.vulnTypeTextColorList[0]
        };
        reportConstants.vulnTypeColorMap[customSeverityService.getCustomSeverity('Low')] = {
            graphColor: reportConstants.vulnTypeColorList[1],
            textColor: reportConstants.vulnTypeTextColorList[1]
        };
        reportConstants.vulnTypeColorMap[customSeverityService.getCustomSeverity('Medium')] = {
            graphColor: reportConstants.vulnTypeColorList[2],
            textColor: reportConstants.vulnTypeTextColorList[2]
        };
        reportConstants.vulnTypeColorMap[customSeverityService.getCustomSeverity('High')] = {
            graphColor: reportConstants.vulnTypeColorList[3],
            textColor: reportConstants.vulnTypeTextColorList[3]
        };
        reportConstants.vulnTypeColorMap[customSeverityService.getCustomSeverity('Critical')] = {
            graphColor: reportConstants.vulnTypeColorList[4],
            textColor: reportConstants.vulnTypeTextColorList[4]
        };
    });

    reportConstants.reportTypes = {
        trending: {
            id: 9,
            name: "trendingTrendingGraph"
        },
        compliance: {
            id: 11,
            name: "complianceTrendingGraph"
        },
        complianceEnterprise: {
            id: 12,
            name: "complianceEnterpriseTrendingGraph"
        }
    };

    return reportConstants;

});

threadfixModule.factory('reportUtilities', function() {

    var reportUtilities = {};
    var drawingDuration = 500;

    reportUtilities.drawTitle = function(svg, w, label, title, y) {
        var teams, apps, tags, i = 0;

        if (label) {
            teams = label.teams;
            apps = label.apps;
            tags = label.tags;
        }

        svg.append("g")
            .append("text")
            .attr("x", w/2)
            .attr("y", y)
            .attr("class", "header")
            .attr("id", title+"_Title")
            .text(title);

        if (teams) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20)
                .attr("class", "title")
                .attr("id", title+"_Teams")
                .text("Team: " + teams);
            i++;
        }

        if (apps) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .attr("id", title+"_Apps")
                .text("Application: " + apps);
            i++;
        }

        if (tags) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .attr("id", title+"_Tags")
                .text("Tags: " + tags)
        }
    };

    reportUtilities.createTeamAppNames = function($scope) {
        var teams, apps, tags, i;

        if ($scope.parameters.teams && $scope.parameters.applications)
            if ($scope.parameters.teams.length === 0
                && $scope.parameters.applications.length === 0) {
                teams = "All";
                apps = "All";
            } else {
                if ($scope.parameters.teams.length > 0) {
                    teams = $scope.parameters.teams[0].name;
                }
                for (i=1; i<$scope.parameters.teams.length; i++) {
                    teams += ", " + $scope.parameters.teams[i].name;
                }

                if ($scope.parameters.applications.length > 0) {
                    apps = $scope.parameters.applications[0].name;
                }
                for (i=1; i<$scope.parameters.applications.length; i++) {
                    apps += ", " + $scope.parameters.applications[i].name;
                }
            }

        if ($scope.parameters.tags) {
            if ($scope.parameters.tags.length === 0) {
                tags = "All";
            } else {
                if ($scope.parameters.tags.length > 0) {
                    tags = $scope.parameters.tags[0].name;
                }
                for (i=1; i<$scope.parameters.tags.length; i++) {
                    tags += ", " + $scope.parameters.tags[i].name;
                }
            }
        }

        if (!$scope.title)
            $scope.title = {};
        $scope.title.teams = teams;
        $scope.title.apps = apps;
        $scope.title.tags = tags;
    };

    reportUtilities.drawTable = function(d3, tableData, divId) {

        var table = d3.select("#" + divId).select("table").attr("class", "table"),
            thead = d3.select("#" + divId).select("thead"),
            tbody = d3.select("#" + divId).select("tbody");

        thead.selectAll('*').remove();
        tbody.selectAll('*').remove();


        thead.selectAll("th")
            .data(d3.keys(tableData[0]))
            .enter().append("th")
            .attr("id", function(d){return d})
            .text(function(d){return d});

        // First create the table rows
        var tr = tbody.selectAll("tr")
            .data(tableData).enter().append("tr")
            .attr("id", function(d, index){return index});

        // Now create the table cells
        var td = tr.selectAll("td")
            .data(function(d){return d3.values(d)})
            .enter().append("td")
            .attr("id", function(d, index){return index})
            .text(function(d) {return d});
    };

    return reportUtilities;

});

threadfixModule.factory('trendingUtilities', function(reportUtilities, customSeverityService) {

    var trendingUtilities = {};
    var startIndex = -1, endIndex = -1;
    var firstHashInList, lastHashInList;

    trendingUtilities.getFirstHashInList = function(){
        return firstHashInList;
    };

    trendingUtilities.getLastHashInList = function() {
        return lastHashInList;
    };

    trendingUtilities.refreshScans = function($scope){
        $scope.loading = true;
        $scope.noData = false;
        var trendingScansData = [];
        reportUtilities.createTeamAppNames($scope);

        trendingUtilities.filterByTime($scope);
        if ($scope.filterScans.length === 0) {
            $scope.noData = true;
            $scope.loading = false;
            return trendingScansData;
        }
        trendingScansData = trendingUtilities.updateDisplayData($scope);
        if (trendingScansData.length === 0) {
            $scope.noData = true;
            $scope.loading = false;
            return trendingScansData;
        }
        $scope.loading = false;

        return trendingScansData;
    };

    trendingUtilities.updateDisplayData = function($scope){
        var hashBefore, hashAfter;
        firstHashInList = null;
        lastHashInList = null;

        reportUtilities.createTeamAppNames($scope);
        var trendingScansData = [];
        $scope.totalVulnsByChannelMap = {};
        $scope.infoVulnsByChannelMap = {};
        $scope.lowVulnsByChannelMap = {};
        $scope.mediumVulnsByChannelMap = {};
        $scope.highVulnsByChannelMap = {};
        $scope.criticalVulnsByChannelMap = {};

        if (startIndex!==-1 && endIndex!==-1) {
            $scope.filterScans.forEach(function(scan, index){
                var _scan = trendingUtilities.filterDisplayData(scan, $scope);

                if (startIndex == index + 1)
                    hashBefore = _scan;
                if (index == endIndex + 1)
                    hashAfter = _scan;
                if ((startIndex===-1 || startIndex <= index)
                    && (endIndex===-1 || endIndex >= index))
                    trendingScansData.push(_scan);
            });

            if (trendingScansData.length > 0) {
                //If this is first scan ever, then set time range from first scan
                if (!hashBefore) {
                    $scope.trendingStartDate = trendingScansData[0].importTime;
                    trendingScansData.push(createEndHash(hashAfter, $scope, trendingScansData));
                } else {
                    trendingScansData.unshift(createStartHash(hashBefore, $scope, trendingScansData));
                    trendingScansData.push(createEndHash(hashAfter, $scope, trendingScansData));
                }
            }
        }
        return trendingScansData;
    };

    var createStartHash = function(hashBefore, $scope, trendingScansData) {
        var startHash = {
            notRealScan : true
        };
        if (trendingScansData.length===0)
            return startHash;

        firstHashInList = trendingScansData[0];

        var keys;

        if (!hashBefore) {
            startHash.importTime = $scope.trendingStartDate;
            keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    startHash[key] = 0;
            });
            firstHashInList = startHash;
        } else {
            var rate1 = (firstHashInList.importTime)-(hashBefore.importTime);
            var rate2 = $scope.trendingStartDate-(hashBefore.importTime);

            startHash.importTime = $scope.trendingStartDate;

            keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    startHash[key] = Math.round(hashBefore[key] +
                    (firstHashInList[key] - hashBefore[key]) / rate1 * rate2);
                }
            });
            firstHashInList = hashBefore;
        }
        return startHash;
    };

    var createEndHash = function(hashAfter, $scope, trendingScansData) {
        var endHash = {
            notRealScan : true
        };
        if (trendingScansData.length===0)
            return endHash;

        lastHashInList = trendingScansData[trendingScansData.length-1];

        var keys;

        if (!hashAfter) {
            endHash.importTime=  $scope.trendingEndDate;
            keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    endHash[key] = lastHashInList[key];
            });
        } else {
            var rate1 = (hashAfter.importTime)-(lastHashInList.importTime);
            var rate2 = $scope.trendingEndDate-(hashAfter.importTime);

            endHash.importTime = $scope.trendingEndDate;

            keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    endHash[key] = Math.round(lastHashInList[key] +
                    (hashAfter[key] - lastHashInList[key]) / rate1 * rate2);
                }
            });
        }
        return endHash;
    };

    trendingUtilities.filterDisplayData = function(scan, $scope) {
        var data = {};
        data.importTime = scan.importTime;
        if ($scope.parameters.showNew) {
            data.New = scan.numberNewVulnerabilities;
        }
        if ($scope.parameters.showResurfaced){
            data.Resurfaced = scan.numberResurfacedVulnerabilities;
        }
        if ($scope.parameters.showTotal) {
            data.Total = calculateTotal(scan, $scope);
        }
        if ($scope.parameters.showClosed){
            data.Closed = scan.numberClosedVulnerabilities;
        }
        if ($scope.parameters.showOld) {
            data.Old = scan.numberOldVulnerabilities;
        }
        if ($scope.parameters.showHidden) {
            data.Hidden = scan.numberHiddenVulnerabilities;
        }
        if ($scope.parameters.severities.info) {
            data[customSeverityService.getCustomSeverity('Info')] = calculateInfo(scan, $scope);
        }
        if ($scope.parameters.severities.low) {
            data[customSeverityService.getCustomSeverity('Low')] = calculateLow(scan, $scope);
        }
        if ($scope.parameters.severities.medium) {
            data[customSeverityService.getCustomSeverity('Medium')] = calculateMedium(scan, $scope);
        }
        if ($scope.parameters.severities.high) {
            data[customSeverityService.getCustomSeverity('High')] = calculateHigh(scan, $scope);
        }
        if ($scope.parameters.severities.critical) {
            data[customSeverityService.getCustomSeverity('Critical')] = calculateCritical(scan, $scope);
        }
        return data;
    };

    var calculateTotal = function(scan, $scope) {
        var adjustedTotal = scan.numberTotalVulnerabilities -
            scan.numberOldVulnerabilities +
            scan.numberOldVulnerabilitiesInitiallyFromThisChannel;
        return trendingTotal($scope.totalVulnsByChannelMap, scan, adjustedTotal);
    };

    var calculateInfo = function(scan, $scope) {
        return trendingTotal($scope.infoVulnsByChannelMap, scan, scan.numberInfoVulnerabilities);
    };

    var calculateLow = function(scan, $scope) {
        return trendingTotal($scope.lowVulnsByChannelMap, scan, scan.numberLowVulnerabilities);
    };

    var calculateMedium = function(scan, $scope) {
        return trendingTotal($scope.mediumVulnsByChannelMap, scan, scan.numberMediumVulnerabilities);
    };

    var calculateHigh = function(scan, $scope) {
        return trendingTotal($scope.highVulnsByChannelMap, scan, scan.numberHighVulnerabilities);
    };

    var calculateCritical = function(scan, $scope) {
        return trendingTotal($scope.criticalVulnsByChannelMap, scan, scan.numberCriticalVulnerabilities);
    };

    var trendingTotal = function(map, scan, newNum) {
        if (scan.applicationChannelId) {
            map[scan.applicationChannelId] = newNum;
        }

        var numTotal = newNum;
        // This code counts in the old vulns from other channels.
        for (var key in map) {
            if (map.hasOwnProperty(key)) {
                if (!scan.applicationChannelId || scan.applicationChannelId != key) {
                    numTotal += map[key];
                }
            }
        }
        return numTotal;
    };

    trendingUtilities.filterByTeamAndApp = function(originalCol, teams, apps) {

        return originalCol.filter(function(scan){
            if (teams.length === 0 && apps.length === 0)
                return true;
            var i;
            for (i=0; i<teams.length; i++) {
                if (scan.team.name === teams[i].name) {
                    return true;
                }
            }
            for (i=0; i<apps.length; i++) {
                if (beginsWith(apps[i].name, scan.team.name + " / ") &&
                    endsWith(apps[i].name, " / " + scan.app.name)) {
                    return true;
                }
            }
            return false;
        });

    };

    trendingUtilities.filterByTag = function(originalCol, tags) {

        return originalCol.filter(function(scan){
            if (tags.length === 0 )
                return true;
            var i, j;
            for (i=0; i<tags.length; i++) {
                for (j=0; j<scan.applicationTags.length; j++) {
                    if (scan.applicationTags[j].name === tags[i].name) {
                        return true;
                    }
                }
            }
            return false;
        });

    };

    trendingUtilities.filterByTime = function($scope) {
        if (!$scope.filterScans || $scope.filterScans.length === 0)
            return;
        $scope.trendingStartDate = undefined;
        $scope.trendingEndDate = undefined;
        startIndex = -1; endIndex = -1;
        if ($scope.parameters.daysOldModifier) {
            $scope.trendingEndDate = new Date();
            if ($scope.parameters.daysOldModifier === "LastYear") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 11, 1);
            } else if ($scope.parameters.daysOldModifier === "LastQuarter") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 2, 1);
            }
        } else {
            if ($scope.parameters.endDate) {
                $scope.trendingEndDate = $scope.parameters.endDate;
            }
            if ($scope.parameters.startDate) {
                $scope.trendingStartDate = $scope.parameters.startDate;
            }
        }

        if (!$scope.trendingStartDate) {
            startIndex = 0;
            $scope.trendingStartDate = $scope.filterScans[0].importTime;
        }
        if (!$scope.trendingEndDate ) {
            endIndex = $scope.filterScans.length - 1;
            $scope.trendingEndDate = new Date();
        }

        $scope.filterScans.some(function(scan, index) {
            if (startIndex!==-1 && endIndex!==-1)
                return true;
            if (startIndex===-1 && $scope.trendingStartDate && $scope.trendingStartDate<=scan.importTime)
                startIndex = index;
            if (endIndex===-1 && $scope.trendingEndDate && $scope.trendingEndDate < scan.importTime)
                endIndex = index - 1;
        });

        if (startIndex===-1 && endIndex!==-1)
            startIndex = 0;
        if (startIndex!==-1 && endIndex===-1)
            endIndex = $scope.filterScans.length - 1;
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

    trendingUtilities.resetFilters = function($scope) {
        if ($scope.savedDefaultTrendingFilter) {
            $scope.selectedFilter = $scope.savedDefaultTrendingFilter;
            $scope.parameters = JSON.parse($scope.savedDefaultTrendingFilter.json);
            if ($scope.parameters.startDate)
                $scope.parameters.startDate = new Date($scope.parameters.startDate);
            if ($scope.parameters.endDate)
                $scope.parameters.endDate = new Date($scope.parameters.endDate);
        } else
            $scope.parameters = {
                teams: [],
                applications: [],
                tags: [],
                severities: {
                    info: true,
                    low: true,
                    medium: true,
                    high: true,
                    critical: true
                },
                showClosed: false,
                showOld: false,
                showHidden: false,
                showTotal: false,
                showNew: false,
                showResurfaced: false,
                daysOldModifier: 'Forever',
                endDate: undefined,
                startDate: undefined
            };
    };

    return trendingUtilities;
});
