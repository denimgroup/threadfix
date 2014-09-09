var threadfixModule = angular.module('threadfix')

threadfixModule.factory('reportExporter', function() {

    var reportExporter = {};

    reportExporter.exportCSV = function() {
    };

    reportExporter.exportPDF = function(d3, width, height, name) {

        var node = d3.select("svg")
            .attr("version", 1.1)
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .node();
        styles(node);

        var html = node.parentNode.innerHTML;

        var imgsrc = 'data:image/svg+xml;base64,'+ btoa(html);
        var img = '<img src="'+imgsrc+'">';
        d3.select("#svgdataurl").html(img);

        var canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        var context = canvas.getContext("2d");

        var image = new Image();
        image.src = imgsrc;
        image.onload = function() {
            context.drawImage(image, 0, 0);

            var canvasdata = canvas.toDataURL("image/png");

            var pngimg = '<img src="'+canvasdata+'">';
            d3.select("#pngdataurl").html(pngimg);

            var a = document.createElement("a");
            a.download = name + ".png";
            a.href = canvasdata;
            a.click();
        };

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
                        console.log(x);
                    }
                }
            }
        };

        var s = document.createElement('style');
        s.setAttribute('type', 'text/css');
        s.innerHTML = "<![CDATA[\n" + used + "\n]]>";

        var defs = document.createElement('defs');
        defs.appendChild(s);
        dom.insertBefore(defs, dom.firstChild);
    };

    return reportExporter;
});


