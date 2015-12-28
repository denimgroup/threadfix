<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Finding Details</title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/finding-source.css"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/syntaxHighlighter/shCore.css"/>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/syntaxHighlighter/shCoreDefault.css"/>
	<cbs:cachebustscript src="/scripts/finding-controller.js"/>
	<cbs:cachebustscript src="/scripts/xregexp-min.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shCore.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushAppleScript.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushBash.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushCpp.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushCSharp.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushCss.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushDelphi.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushGroovy.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushHaxe.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushJava.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushJScript.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushPerl.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushPhp.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushPlain.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushPython.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushRuby.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushSass.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushSql.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushTAP.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushTypeScript.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushVb.js"/>
	<cbs:cachebustscript src="/scripts/syntaxHighlighter/shBrushXml.js"/>
	<script type="text/javascript">
		SyntaxHighlighter.defaults['toolbar'] = false;
		SyntaxHighlighter.defaults['useScriptTags'] = false;
	</script>
</head>

<body id="apps" ng-controller="FindingController">
	<%@ include file="/WEB-INF/views/scans/finding/findingHeader.jsp" %>
	<%@ include file="/WEB-INF/views/angular-init.jspf"%>
	<%@ include file="/WEB-INF/views/scans/finding/detail.jsp" %>
</body>
