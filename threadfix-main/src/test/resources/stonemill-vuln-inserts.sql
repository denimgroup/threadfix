-- INSERT THE CHANNELS
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Fortify 360', 'http://www.fortify.com', '2.5.0');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Microsoft CAT.NET', 'http://msdn.microsoft.com/en-us/security/default.aspx', '1 CTP');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Checkmarx CxSuite', 'http://www.checkmarx.com/index.aspx', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('FindBugs', 'http://findbugs.sourceforge.net/', '1.3.9');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('OWASP Orizon', 'http://www.owasp.org/index.php/Category:OWASP_Orizon_Project', '1.19');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan Source Edition', 'http://www-01.ibm.com/software/rational/products/appscan/source/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan', 'http://www-01.ibm.com/software/awdtools/appscan/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Mavituna Security Netsparker', 'http://www.mavitunasecurity.com/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('WhiteHat Sentinel', 'http://www.whitehatsec.com/home/services/services.html', '-');

SET @fortify_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Fortify 360');
SET @cat_net_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Microsoft CAT.NET');
SET @checkmarx_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Checkmarx CxSuite');
SET @findbugs_channel_id := (SELECT id FROM ChannelType WHERE Name = 'FindBugs');
SET @orizon_channel_id := (SELECT id FROM ChannelType WHERE Name = 'OWASP Orizon');
SET @appscanse_channel_id := (SELECT id FROM ChannelType WHERE Name = 'IBM Rational AppScan Source Edition');
SET @appscan_channel_id := (SELECT id FROM ChannelType WHERE Name = 'IBM Rational AppScan');
SET @netsparker_net_channel_id := (SELECT id FROM ChannelType WHERE Name = 'Mavituna Security Netsparker');
SET @sentinel_channel_id := (SELECT id FROM ChannelType WHERE Name = 'WhiteHat Sentinel');

INSERT INTO WafType (Name) VALUES ('Snort');
INSERT INTO WafType (Name) VALUES ('mod_security');
INSERT INTO WafType (Name) VALUES ('ESAPI WAF');

SET @snort_waf_type_id := (SELECT id FROM WafType WHERE Name = 'Snort');
SET @mod_security_waf_type_id := (SELECT id FROM WafType WHERE Name = 'mod_security');
SET @esapi_waf_waf_type_id := (SELECT id FROM WafType WHERE Name = 'ESAPI WAF');

INSERT INTO DefectTrackerType (Name) VALUES ('Bugzilla');
INSERT INTO DefectTrackerType (Name) VALUES ('Jira');

-- INSERT INTO applicationdefecttracker (password, projectname, url, username, defecttrackerid)
--	VALUES ('Testing92JIRA', 'TEST', 'http://dgtest2.onjira.com/rpc/xmlrpc', 'dgtestuser', @jira_defect_tracker_id);
-- INSERT INTO applicationdefecttracker (password, projectname, url, username, defecttrackerid)
-- 	VALUES ('bugzilla', 'TEST', 'http://dgvm-vulnmgr.denimgroup.com:8080/bugzilla/xmlrpc.cgi', 'mcollins@denimgroup.com', @bugzilla_defect_tracker_id);

SET @jira_defect_tracker_id := (SELECT id FROM DefectTrackerType WHERE Name = 'Jira');
SET @bugzilla_defect_tracker_id := (SELECT id FROM DefectTrackerType WHERE Name = 'Bugzilla');

-- INSERT GENERIC MAPPINGS
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Location', '1');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Environment', '2');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Technology-specific Environment Issues', '3');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Environment Issues', '4');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Data Transmission Without Encryption', '5');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Insufficient Session-ID Length', '6');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Missing Custom Error Page', '7');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Entity Bean Declared Remote', '8');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Weak Access Permissions for EJB Methods', '9');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Environment Issues', '10');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Creating Debug Binary', '11');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Missing Custom Error Page', '12');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Password in Configuration File', '13');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Compiler Removal of Code to Clear Buffers', '14');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Control of System or Configuration Setting', '15');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Configuration', '16');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Code', '17');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Source Code', '18');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Data Handling', '19');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Input Validation', '20');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Pathname Traversal and Equivalence Errors', '21');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'')', '22');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Relative Path Traversal', '23');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''../filedir''', '24');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''/../filedir''', '25');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''/dir/../filename''', '26');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''dir/../../filename''', '27');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''..\filedir''', '28');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''\..\filename''', '29');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''\dir\..\filename''', '30');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''dir\..\..\filename''', '31');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''...'' (Triple Dot)', '32');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''....'' (Multiple Dot)', '33');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''....//''', '34');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''.../...//''', '35');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Absolute Path Traversal', '36');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''/absolute/pathname/here''', '37');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''\absolute\pathname\here''', '38');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''C:dirname''', '39');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Traversal: ''\\UNC\share\name\'' (Windows UNC Share)', '40');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Resolution of Path Equivalence', '41');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filename.'' (Trailing Dot)', '42');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filename....'' (Multiple Trailing Dot)', '43');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''file.name'' (Internal Dot)', '44');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''file...name'' (Multiple Internal Dot)', '45');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filename '' (Trailing Space)', '46');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: '' filename (Leading Space)', '47');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''file name'' (Internal Whitespace)', '48');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filename/'' (Trailing Slash)', '49');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''//multiple/leading/slash''', '50');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''/multiple//internal/slash''', '51');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''/multiple/trailing/slash//''', '52');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''\multiple\\internal\backslash''', '53');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filedir\'' (Trailing Backslash)', '54');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''/./'' (Single Dot Directory)', '55');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''filedir*'' (Wildcard)', '56');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: ''fakedir/../realdir/filename''', '57');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Path Equivalence: Windows 8.3 Filename', '58');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Link Resolution Before File Access (''Link Following'')', '59');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UNIX Path Link Problems', '60');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UNIX Symbolic Link (Symlink) Following', '61');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UNIX Hard Link', '62');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Windows Path Link Problems', '63');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Windows Shortcut Following (.LNK)', '64');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Windows Hard Link', '65');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of File Names that Identify Virtual Resources', '66');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Windows Device Names', '67');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Windows Virtual File Problems', '68');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Windows ::DATA Alternate Data Stream', '69');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Mac Virtual File Problems', '70');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Apple ''.DS_Store''', '71');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Apple HFS+ Alternate Data Stream Path', '72');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Control of File Name or Path', '73');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data into a Different Plane (''Injection'')', '74');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)', '75');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Resolve Equivalent Special Elements into a Different Plane', '76');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements used in a Command (''Command Injection'')', '77');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements used in an OS Command (''OS Command Injection'')', '78');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Preserve Web Page Structure (''Cross-site Scripting'')', '79');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Script-Related HTML Tags in a Web Page (Basic XSS)', '80');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Script in an Error Message Web Page', '81');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Script in Attributes of IMG Tags in a Web Page', '82');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Script in Attributes in a Web Page', '83');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Resolve Encoded URI Schemes in a Web Page', '84');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Doubled Character XSS Manipulations', '85');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Invalid Characters in Identifiers in Web Pages', '86');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Alternate XSS Syntax', '87');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Argument Injection or Modification', '88');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements used in an SQL Command (''SQL Injection'')', '89');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data into LDAP Queries (''LDAP Injection'')', '90');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('XML Injection (aka Blind XPath Injection)', '91');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED: Improper Sanitization of Custom Special Characters', '92');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize CRLF Sequences (''CRLF Injection'')', '93');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Control Generation of Code (''Code Injection'')', '94');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Directives in Dynamically Evaluated Code (''Eval Injection'')', '95');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Directives in Statically Saved Code (''Static Code Injection'')', '96');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Server-Side Includes (SSI) Within a Web Page', '97');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Control of Filename for Include/Require Statement in PHP Program (''PHP File Inclusion'')', '98');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Control of Resource Identifiers (''Resource Injection'')', '99');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Technology-Specific Input Validation Problems', '100');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts Validation Problems', '101');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Duplicate Validation Forms', '102');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Incomplete validate() Method Definition', '103');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Form Bean Does Not Extend Validation Class', '104');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Form Field Without Validator', '105');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Plug-in Framework not in Use', '106');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Unused Validation Form', '107');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Unvalidated Action Form', '108');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Validator Turned Off', '109');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Validator Without Form Field', '110');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Direct Use of Unsafe JNI', '111');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing XML Validation', '112');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize CRLF Sequences in HTTP Headers (''HTTP Response Splitting'')', '113');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Process Control', '114');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Misinterpretation of Input', '115');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Encoding or Escaping of Output', '116');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Output Sanitization for Logs', '117');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Access of Indexable Resource (''Range Error'')', '118');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Constrain Operations within the Bounds of a Memory Buffer', '119');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Copy without Checking Size of Input (''Classic Buffer Overflow'')', '120');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Stack-based Buffer Overflow', '121');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Heap-based Buffer Overflow', '122');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Write-what-where Condition', '123');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Underwrite (''Buffer Underflow'')', '124');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Out-of-bounds Read', '125');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Over-read', '126');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Under-read', '127');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Wrap-around Error', '128');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Validation of Array Index', '129');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Length Parameter Inconsistency ', '130');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Calculation of Buffer Size', '131');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): Miscalculated Null Termination', '132');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('String Errors', '133');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncontrolled Format String', '134');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Calculation of Multi-Byte String Length', '135');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Type Errors', '136');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Representation Errors', '137');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Special Elements', '138');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED: General Special Element Problems', '139');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Delimiters', '140');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Parameter/Argument Delimiters', '141');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Value Delimiters', '142');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Record Delimiters', '143');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Line Delimiters', '144');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Section Delimiters', '145');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Expression/Command Delimiters', '146');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Input Terminators', '147');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Input Leaders', '148');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Quoting Syntax', '149');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Escape, Meta, or Control Sequences', '150');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Comment Delimiters', '151');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Macro Symbols', '152');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Substitution Characters', '153');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Variable Name Delimiters', '154');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Wildcards or Matching Symbols', '155');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Whitespace', '156');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Paired Delimiters', '157');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Null Byte or NUL Character', '158');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Special Element', '159');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Leading Special Elements', '160');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Multiple Leading Special Elements', '161');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Trailing Special Elements', '162');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Multiple Trailing Special Elements', '163');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Internal Special Elements', '164');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of Multiple Internal Special Elements', '165');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Missing Special Element', '166');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Additional Special Element', '167');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Resolve Inconsistent Special Elements', '168');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Technology-Specific Special Elements', '169');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Null Termination', '170');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cleansing, Canonicalization, and Comparison Errors', '171');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Encoding Error', '172');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Alternate Encoding', '173');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Double Decoding of the Same Data', '174');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Mixed Encoding', '175');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Unicode Encoding', '176');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle URL Encoding (Hex Encoding)', '177');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Resolve Case Sensitivity', '178');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Early Validation', '179');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Validate Before Canonicalize', '180');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Validate Before Filter', '181');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Collapse of Data Into Unsafe Value', '182');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Permissive Whitelist', '183');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Blacklist', '184');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Regular Expression', '185');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Overly Restrictive Regular Expression', '186');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Partial Comparison', '187');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Data/Memory Layout', '188');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Numeric Errors', '189');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Integer Overflow or Wraparound', '190');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Integer Underflow (Wrap or Wraparound)', '191');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Integer Coercion Error', '192');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Off-by-one Error', '193');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unexpected Sign Extension', '194');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Signed to Unsigned Conversion Error', '195');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unsigned to Signed Conversion Error', '196');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Numeric Truncation Error', '197');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Incorrect Byte Ordering', '198');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Management Errors', '199');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure', '200');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Sent Data', '201');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privacy Leak through Data Queries', '202');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure Through Discrepancy', '203');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Response Discrepancy Information Leak', '204');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure Through Behavioral Discrepancy', '205');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Internal Behavioral Inconsistency Information Leak', '206');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure Through an External Behavioral Inconsistency', '207');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Timing Discrepancy Information Leak', '208');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Exposure Through an Error Message', '209');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Product-Generated Error Message Information Leak', '210');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Product-External Error Message Information Leak', '211');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Cross-boundary Removal of Sensitive Data', '212');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Intended Information Leak', '213');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Process Environment Information Leak', '214');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Debug Information', '215');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Containment Errors (Container Errors)', '216');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED: Failure to Protect Stored Data from Modification', '217');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): Failure to provide confidentiality for stored data', '218');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Sensitive Data Under Web Root', '219');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Sensitive Data Under FTP Root', '220');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Loss or Omission', '221');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Truncation of Security-relevant Information', '222');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Omission of Security-relevant Information', '223');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Obscured Security-relevant Information by Alternate Name', '224');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): General Information Management Problems', '225');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Sensitive Information Uncleared Before Release', '226');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Fulfill API Contract (''API Abuse'')', '227');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Syntactically Invalid Structure', '228');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Values', '229');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Missing Values', '230');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Extra Values', '231');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Undefined Values', '232');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Parameter Problems', '233');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Missing Parameter', '234');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Extra Parameters', '235');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Undefined Parameters', '236');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Structural Elements', '237');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Incomplete Structural Elements', '238');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Incomplete Element', '239');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Inconsistent Structural Elements', '240');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Unexpected Data Type', '241');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Inherently Dangerous Function', '242');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Change Working Directory in chroot Jail', '243');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Clear Heap Memory Before Release (''Heap Inspection'')', '244');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Bad Practices: Direct Management of Connections', '245');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Bad Practices: Direct Use of Sockets', '246');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on DNS Lookups in a Security Decision', '247');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncaught Exception', '248');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED: Often Misused: Path Manipulation', '249');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Execution with Unnecessary Privileges', '250');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Often Misused: String Management', '251');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unchecked Return Value', '252');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Check of Function Return Value', '253');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Security Features', '254');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Credentials Management', '255');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage of a Password', '256');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Storing Passwords in a Recoverable Format', '257');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Empty Password in Configuration File', '258');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Hard-coded Password', '259');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Password in Configuration File', '260');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weak Cryptography for Passwords', '261');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Not Using Password Aging', '262');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Password Aging with Long Expiration', '263');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Permissions, Privileges, and Access Controls', '264');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privilege / Sandbox Issues', '265');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Privilege Assignment', '266');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privilege Defined With Unsafe Actions', '267');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privilege Chaining', '268');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Privilege Management', '269');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privilege Context Switching Error', '270');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privilege Dropping / Lowering Errors', '271');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Least Privilege Violation', '272');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Check for Dropped Privileges', '273');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Insufficient Privileges', '274');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Permission Issues', '275');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Default Permissions', '276');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insecure Inherited Permissions', '277');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insecure Preserved Inherited Permissions', '278');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Execution-Assigned Permissions', '279');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Insufficient Permissions or Privileges ', '280');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Preservation of Permissions', '281');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Ownership Management', '282');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unverified Ownership', '283');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access Control (Authorization) Issues', '284');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Access Control (Authorization)', '285');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect User Management', '286');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Authentication', '287');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass Using an Alternate Path or Channel', '288');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass by Alternate Name', '289');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass by Spoofing', '290');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trusting Self-reported IP Address', '291');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trusting Self-reported DNS Name', '292');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Using Referer Field for Authentication', '293');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass by Capture-replay', '294');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Certificate Issues', '295');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Following of Chain of Trust for Certificate Validation', '296');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Validation of Host-specific Certificate Data', '297');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Validation of Certificate Expiration', '298');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Check for Certificate Revocation', '299');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Channel Accessible by Non-Endpoint (''Man-in-the-Middle'')', '300');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reflection Attack in an Authentication Protocol', '301');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass by Assumed-Immutable Data', '302');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Implementation of Authentication Algorithm', '303');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Critical Step in Authentication', '304');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass by Primary Weakness', '305');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Authentication for Critical Function', '306');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Restriction of Excessive Authentication Attempts', '307');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Single-factor Authentication', '308');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Password System for Primary Authentication', '309');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cryptographic Issues', '310');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Encryption of Sensitive Data', '311');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cleartext Storage of Sensitive Information', '312');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in a File or on Disk', '313');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in the Registry', '314');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in a Cookie', '315');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in Memory', '316');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in GUI', '317');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Plaintext Storage in Executable', '318');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cleartext Transmission of Sensitive Information', '319');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Key Management Errors', '320');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Hard-coded Cryptographic Key', '321');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Key Exchange without Entity Authentication', '322');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reusing a Nonce, Key Pair in Encryption', '323');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of a Key Past its Expiration Date', '324');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Required Cryptographic Step', '325');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Inadequate Encryption Strength', '326');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of a Broken or Risky Cryptographic Algorithm', '327');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reversible One-Way Hash', '328');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Not Using a Random IV with CBC Mode', '329');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Insufficiently Random Values', '330');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Entropy', '331');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Entropy in PRNG', '332');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Insufficient Entropy in TRNG', '333');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Small Space of Random Values', '334');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('PRNG Seed Error', '335');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Same Seed in PRNG', '336');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Predictable Seed in PRNG', '337');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Cryptographically Weak PRNG', '338');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Small Seed Space in PRNG', '339');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Predictability Problems', '340');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Predictable from Observable State', '341');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Predictable Exact Value from Previous Values', '342');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Predictable Value Range from Previous Values', '343');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Invariant Value in Dynamically Changing Context', '344');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Verification of Data Authenticity', '345');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Origin Validation Error', '346');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Verification of Cryptographic Signature', '347');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Less Trusted Source', '348');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Acceptance of Extraneous Untrusted Data With Trusted Data', '349');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improperly Trusted Reverse DNS', '350');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Type Distinction', '351');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Cross-Site Request Forgery (CSRF)', '352');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Add Integrity Check Value', '353');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Validation of Integrity Check Value', '354');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('User Interface Security Issues', '355');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Product UI does not Warn User of Unsafe Actions', '356');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient UI Warning of Dangerous Operations', '357');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improperly Implemented Security Check for Standard', '358');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Privacy Violation', '359');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trust of System Event Data', '360');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Time and State', '361');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Race Condition', '362');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Race Condition Enabling Link Following', '363');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Signal Handler Race Condition', '364');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Race Condition in Switch', '365');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Race Condition within a Thread', '366');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Time-of-check Time-of-use (TOCTOU) Race Condition', '367');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Context Switching Race Condition', '368');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Divide By Zero', '369');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Check for Certificate Revocation after Initial Check', '370');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('State Issues', '371');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Internal State Distinction', '372');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('State Synchronization Error', '373');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Mutable Objects Passed by Reference', '374');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Passing Mutable Objects to an Untrusted Method', '375');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Temporary File Issues', '376');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insecure Temporary File', '377');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Creation of Temporary File With Insecure Permissions', '378');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Creation of Temporary File in Directory with Incorrect Permissions', '379');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Technology-Specific Time and State Issues', '380');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Time and State Issues', '381');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Bad Practices: Use of System.exit()', '382');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Bad Practices: Direct Use of Threads', '383');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Session Fixation', '384');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Covert Timing Channel', '385');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Symbolic Name not Mapping to Correct Object', '386');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Signal Errors', '387');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Error Handling', '388');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Error Conditions, Return Values, Status Codes', '389');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Detection of Error Condition Without Action', '390');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unchecked Error Condition', '391');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Report Error in Status Code', '392');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Return of Wrong Status Code', '393');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unexpected Status Code or Return Value', '394');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of NullPointerException Catch to Detect NULL Pointer Dereference', '395');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Declaration of Catch for Generic Exception', '396');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Declaration of Throws for Generic Exception', '397');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Indicator of Poor Code Quality', '398');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Resource Management Errors', '399');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncontrolled Resource Consumption (''Resource Exhaustion'')', '400');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Release Memory Before Removing Last Reference (''Memory Leak'')', '401');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Transmission of Private Resources into a New Sphere (''Resource Leak'')', '402');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UNIX File Descriptor Leak', '403');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Resource Shutdown or Release', '404');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Asymmetric Resource Consumption (Amplification)', '405');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Control of Network Message Volume (Network Amplification)', '406');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Algorithmic Complexity', '407');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Early Amplification', '408');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Highly Compressed Data (Data Amplification)', '409');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Resource Pool', '410');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Resource Locking Problems', '411');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unrestricted Externally Accessible Lock', '412');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Resource Locking', '413');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Lock Check', '414');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Double Free', '415');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use After Free', '416');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Channel and Path Errors', '417');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Channel Errors', '418');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unprotected Primary Channel', '419');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unprotected Alternate Channel', '420');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Race Condition During Access to Alternate Channel', '421');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unprotected Windows Messaging Channel (''Shatter'')', '422');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): Proxied Trusted Channel', '423');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Protect Alternate Path', '424');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Direct Request (''Forced Browsing'')', '425');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Untrusted Search Path', '426');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncontrolled Search Path Element', '427');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unquoted Search Path or Element', '428');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Handler Errors', '429');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Deployment of Wrong Handler', '430');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Handler', '431');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Dangerous Handler not Disabled During Sensitive Operations', '432');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unparsed Raw Web Content Delivery', '433');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unrestricted Upload of File with Dangerous Type', '434');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Interaction Error', '435');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Interpretation Conflict', '436');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Model of Endpoint Features', '437');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Behavioral Problems', '438');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Behavioral Change in New Version or Environment', '439');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Expected Behavior Violation', '440');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unintended Proxy/Intermediary', '441');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Web Problems', '442');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): HTTP response splitting', '443');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Inconsistent Interpretation of HTTP Requests (''HTTP Request Smuggling'')', '444');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('User Interface Errors', '445');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UI Discrepancy for Security Feature', '446');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unimplemented or Unsupported Feature in UI', '447');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Obsolete Feature in UI', '448');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('The UI Performs the Wrong Action', '449');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Multiple Interpretations of UI Input', '450');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('UI Misrepresentation of Critical Information', '451');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Initialization and Cleanup Errors', '452');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insecure Default Variable Initialization', '453');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Initialization of Trusted Variables or Data Stores', '454');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Non-exit on Failed Initialization', '455');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Initialization', '456');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Uninitialized Variable', '457');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED: Incorrect Initialization', '458');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Cleanup', '459');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Cleanup on Thrown Exception', '460');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Data Structure Issues', '461');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Duplicate Key in Associative List (Alist)', '462');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Deletion of Data Structure Sentinel', '463');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Addition of Data Structure Sentinel', '464');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Pointer Issues', '465');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Return of Pointer Value Outside of Expected Range', '466');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of sizeof() on a Pointer Type', '467');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Pointer Scaling', '468');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Pointer Subtraction to Determine Size', '469');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Externally-Controlled Input to Select Classes or Code (''Unsafe Reflection'')', '470');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Modification of Assumed-Immutable Data (MAID)', '471');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Control of Assumed-Immutable Web Parameter', '472');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('PHP External Variable Modification', '473');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Function with Inconsistent Implementations', '474');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Undefined Behavior for Input to API', '475');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('NULL Pointer Dereference', '476');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Obsolete Functions', '477');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Default Case in Switch Statement', '478');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unsafe Function Call from a Signal Handler', '479');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Incorrect Operator', '480');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Assigning instead of Comparing', '481');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Comparing instead of Assigning', '482');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Block Delimitation', '483');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Omitted Break Statement in Switch', '484');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Encapsulation', '485');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Comparison of Classes by Name', '486');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Package-level Scope', '487');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Data Leak Between Sessions', '488');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Leftover Debug Code', '489');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Mobile Code Issues', '490');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Public cloneable() Method Without Final (''Object Hijack'')', '491');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Inner Class Containing Sensitive Data', '492');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Critical Public Variable Without Final Modifier', '493');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Download of Code Without Integrity Check', '494');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Private Array-Typed Field Returned From A Public Method', '495');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Public Data Assigned to Private Array-Typed Field', '496');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of System Data to an Unauthorized Control Sphere', '497');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak through Class Cloning', '498');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Serializable Class Containing Sensitive Data', '499');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Public Static Field Not Marked Final', '500');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trust Boundary Violation', '501');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Deserialization of Untrusted Data', '502');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Byte/Object Code', '503');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Motivation/Intent', '504');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Intentionally Introduced Weakness', '505');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Embedded Malicious Code', '506');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trojan Horse', '507');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Non-Replicating Malicious Code', '508');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Replicating Malicious Code (Virus or Worm)', '509');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trapdoor', '510');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Logic/Time Bomb', '511');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Spyware', '512');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Intentionally Introduced Nonmalicious Weakness', '513');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Covert Channel', '514');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Covert Storage Channel', '515');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('DEPRECATED (Duplicate): Covert Timing Channel', '516');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Other Intentional, Nonmalicious Weakness', '517');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Inadvertently Introduced Weakness', '518');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('.NET Environment Issues', '519');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('.NET Misconfiguration: Use of Impersonation', '520');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weak Password Requirements', '521');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficiently Protected Credentials', '522');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unprotected Transport of Credentials', '523');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Caching', '524');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Browser Caching', '525');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Environmental Variables', '526');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of CVS Repository to an Unauthorized Control Sphere', '527');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of Core Dump File to an Unauthorized Control Sphere', '528');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of Access Control List Files to an Unauthorized Control Sphere', '529');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of Backup File to an Unauthorized Control Sphere', '530');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Test Code', '531');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Log Files', '532');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Server Log Files', '533');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Debug Log Files', '534');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Shell Error Message', '535');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Servlet Runtime Error Message', '536');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Java Runtime Error Message', '537');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('File and Directory Information Exposure', '538');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Persistent Cookies', '539');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Source Code', '540');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Include Source Code', '541');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Cleanup Log Files', '542');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Singleton Pattern in a Non-thread-safe Manner', '543');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Use a Standardized Error Handling Mechanism', '544');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Dynamic Class Loading', '545');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Suspicious Comment', '546');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Hard-coded, Security-relevant Constants', '547');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Directory Listing', '548');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Password Field Masking', '549');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Server Error Message', '550');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order: Authorization Before Parsing and Canonicalization', '551');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Files or Directories Accessible to External Parties', '552');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Command Shell in Externally Accessible Directory', '553');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Not Using Input Validation Framework', '554');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Misconfiguration: Plaintext Password in Configuration File', '555');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('ASP.NET Misconfiguration: Use of Identity Impersonation', '556');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Concurrency Issues', '557');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of getlogin() in Multithreaded Application', '558');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Often Misused: Arguments and Parameters', '559');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of umask() with chmod-style Argument', '560');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Dead Code', '561');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Return of Stack Variable Address', '562');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unused Variable', '563');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('SQL Injection: Hibernate', '564');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Cookies without Validation and Integrity Checking', '565');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access Control Bypass Through User-Controlled SQL Primary Key', '566');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unsynchronized Access to Shared Data', '567');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('finalize() Method Without super.finalize()', '568');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Expression Issues', '569');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Expression is Always False', '570');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Expression is Always True', '571');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Call to Thread run() instead of start()', '572');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Follow Specification', '573');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('EJB Bad Practices: Use of Synchronization Primitives', '574');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('EJB Bad Practices: Use of AWT Swing', '575');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('EJB Bad Practices: Use of Java I/O', '576');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('EJB Bad Practices: Use of Sockets', '577');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('EJB Bad Practices: Use of Class Loader', '578');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Bad Practices: Non-serializable Object Stored in Session', '579');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('clone() Method Without super.clone()', '580');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Object Model Violation: Just One of Equals and Hashcode Defined', '581');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Array Declared Public, Final, and Static', '582');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('finalize() Method Declared Public', '583');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Return Inside Finally Block', '584');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Empty Synchronized Block', '585');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Explicit Call to Finalize()', '586');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Assignment of a Fixed Address to a Pointer', '587');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Attempt to Access Child of a Non-structure Pointer', '588');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Call to Non-ubiquitous API', '589');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Free of Memory not on the Heap', '590');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Sensitive Data Storage in Improperly Locked Memory', '591');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass Issues', '592');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created', '593');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('J2EE Framework: Saving Unserializable Objects to Disk', '594');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Comparison of Object References Instead of Object Contents', '595');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Semantic Object Comparison', '596');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Wrong Operator in String Comparison', '597');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Query Strings in GET Request', '598');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trust of OpenSSL Certificate Without Validation', '599');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Catch All Exceptions in Servlet ', '600');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('URL Redirection to Untrusted Site (''Open Redirect'')', '601');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Client-Side Enforcement of Server-Side Security', '602');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Client-Side Authentication', '603');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Deprecated Entries', '604');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Multiple Binds to the Same Port', '605');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unchecked Input for Loop Condition', '606');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Public Static Final Field References Mutable Object', '607');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Struts: Non-private Field in ActionForm Class', '608');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Double-Checked Locking', '609');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Externally Controlled Reference to a Resource in Another Sphere', '610');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through XML External Entity File Disclosure', '611');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Indexing of Private Data', '612');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Session Expiration', '613');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Sensitive Cookie in HTTPS Session Without ''Secure'' Attribute', '614');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak Through Comments', '615');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Identification of Uploaded File Variables (PHP)', '616');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reachable Assertion', '617');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposed Unsafe ActiveX Method', '618');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Dangling Database Cursor (''Cursor Injection'')', '619');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unverified Password Change', '620');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Variable Extraction Error', '621');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unvalidated Function Hook Arguments', '622');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unsafe ActiveX Control Marked Safe For Scripting', '623');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Executable Regular Expression Error', '624');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Permissive Regular Expression', '625');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Null Byte Interaction Error (Poison Null Byte)', '626');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Dynamic Variable Evaluation', '627');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call with Incorrectly Specified Arguments', '628');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in OWASP Top Ten (2007)', '629');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses Examined by SAMATE', '630');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Resource-specific Weaknesses', '631');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses that Affect Files or Directories', '632');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses that Affect Memory', '633');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses that Affect System Processes', '634');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses Used by NVD', '635');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Not Failing Securely (''Failing Open'')', '636');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Use Economy of Mechanism', '637');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Use Complete Mediation', '638');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access Control Bypass Through User-Controlled Key', '639');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weak Password Recovery Mechanism for Forgotten Password', '640');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Filtering of File and Other Resource Names for Executable Content', '641');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Control of Critical State Data', '642');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data within XPath Expressions (''XPath injection'')', '643');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Sanitization of HTTP Headers for Scripting Syntax', '644');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Overly Restrictive Account Lockout Mechanism', '645');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on File Name or Extension of Externally-Supplied File', '646');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Non-Canonical URL Paths for Authorization Decisions', '647');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Use of Privileged APIs', '648');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking', '649');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Trusting HTTP Permission Methods on the Server Side', '650');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Information Leak through WSDL File', '651');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Sanitize Data within XQuery Expressions (''XQuery Injection'')', '652');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Compartmentalization', '653');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on a Single Factor in a Security Decision', '654');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Psychological Acceptability', '655');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Security through Obscurity', '656');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Violation of Secure Design Principles', '657');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in Software Written in C', '658');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in Software Written in C++', '659');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in Software Written in Java', '660');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in Software Written in PHP', '661');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Synchronization', '662');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of a Non-reentrant Function in an Unsynchronized Context', '663');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Control of a Resource Through its Lifetime', '664');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Initialization', '665');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Operation on Resource in Wrong Phase of Lifetime', '666');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Locking', '667');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposure of Resource to Wrong Sphere', '668');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Resource Transfer Between Spheres', '669');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Always-Incorrect Control Flow Implementation', '670');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Lack of Administrator Control over Security', '671');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Operation on a Resource after Expiration or Release', '672');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('External Influence of Sphere Definition', '673');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncontrolled Recursion', '674');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Duplicate Operations on Resource', '675');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Potentially Dangerous Function', '676');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weakness Base Elements', '677');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Composites', '678');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Chain Elements', '679');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Integer Overflow to Buffer Overflow', '680');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Conversion between Numeric Types', '681');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Calculation', '682');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call With Incorrect Order of Arguments', '683');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Provide Specified Functionality', '684');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call With Incorrect Number of Arguments', '685');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call With Incorrect Argument Type', '686');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call With Incorrectly Specified Argument Value', '687');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Function Call With Incorrect Variable or Reference as Argument', '688');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Permission Race Condition During Resource Copy', '689');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unchecked Return Value to NULL Pointer Dereference', '690');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Control Flow Management', '691');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Blacklist to Cross-Site Scripting', '692');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Protection Mechanism Failure', '693');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Multiple Resources with Duplicate Identifier', '694');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Low-Level Functionality', '695');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Behavior Order', '696');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Comparison', '697');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Redirect Without Exit', '698');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Development Concepts', '699');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Seven Pernicious Kingdoms', '700');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses Introduced During Design', '701');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses Introduced During Implementation', '702');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Failure to Handle Exceptional Conditions', '703');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Type Conversion or Cast', '704');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Control Flow Scoping', '705');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Incorrectly-Resolved Name or Reference', '706');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Enforcement of Message or Data Structure', '707');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Ownership Assignment', '708');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Named Chains', '709');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Coding Standards Violation', '710');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in OWASP Top Ten (2004)', '711');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A1 - Cross Site Scripting (XSS)', '712');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A2 - Injection Flaws', '713');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A3 - Malicious File Execution', '714');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference', '715');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery (CSRF)', '716');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling', '717');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management', '718');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A8 - Insecure Cryptographic Storage', '719');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A9 - Insecure Communications', '720');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2007 Category A10 - Failure to Restrict URL Access', '721');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A1 - Unvalidated Input', '722');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A2 - Broken Access Control', '723');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management', '724');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A4 - Cross-Site Scripting (XSS) Flaws', '725');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A5 - Buffer Overflows', '726');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A6 - Injection Flaws', '727');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A7 - Improper Error Handling', '728');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A8 - Insecure Storage', '729');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A9 - Denial of Service', '730');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('OWASP Top Ten 2004 Category A10 - Insecure Configuration Management', '731');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Permission Assignment for Critical Resource', '732');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Compiler Optimization Removal or Modification of Security-critical Code', '733');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses Addressed by the CERT C Secure Coding Standard', '734');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 01 - Preprocessor (PRE)', '735');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 02 - Declarations and Initialization (DCL)', '736');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 03 - Expressions (EXP)', '737');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 04 - Integers (INT)', '738');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 05 - Floating Point (FLP)', '739');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 06 - Arrays (ARR)', '740');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 07 - Characters and Strings (STR)', '741');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 08 - Memory Management (MEM)', '742');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 09 - Input Output (FIO)', '743');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 10 - Environment (ENV)', '744');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 11 - Signals (SIG)', '745');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 12 - Error Handling (ERR)', '746');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 49 - Miscellaneous (MSC)', '747');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('CERT C Secure Coding Section 50 - POSIX (POS)', '748');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposed Dangerous Method or Function', '749');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in the 2009 CWE/SANS Top 25 Most Dangerous Programming Errors', '750');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2009 Top 25 - Insecure Interaction Between Components', '751');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2009 Top 25 - Risky Resource Management', '752');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2009 Top 25 - Porous Defenses', '753');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Check for Unusual or Exceptional Conditions', '754');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Handling of Exceptional Conditions', '755');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Custom Error Page', '756');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Selection of Less-Secure Algorithm During Negotiation (''Algorithm Downgrade'')', '757');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Undefined, Unspecified, or Implementation-Defined Behavior', '758');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of a One-Way Hash without a Salt', '759');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of a One-Way Hash with a Predictable Salt', '760');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Free of Pointer not at Start of Buffer', '761');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Mismatched Memory Management Routines', '762');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Release of Invalid Pointer or Reference', '763');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Multiple Locks of a Critical Resource', '764');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Multiple Unlocks of a Critical Resource', '765');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Critical Variable Declared Public', '766');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access to Critical Private Variable via Public Method', '767');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incorrect Short Circuit Evaluation', '768');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('File Descriptor Exhaustion', '769');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Allocation of Resources Without Limits or Throttling', '770');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Reference to Active Allocated Resource', '771');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Release of Resource after Effective Lifetime', '772');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Reference to Active File Descriptor or Handle', '773');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Allocation of File Descriptors or Handles Without Limits or Throttling', '774');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Missing Release of File Descriptor or Handle after Effective Lifetime', '775');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Unrestricted Recursive Entity References in DTDs (''XML Bomb'')', '776');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Regular Expression without Anchors', '777');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Insufficient Logging', '778');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Logging of Excessive Data', '779');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of RSA Algorithm without OAEP', '780');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code', '781');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Exposed IOCTL with Insufficient Access Control', '782');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Operator Precedence Logic Error', '783');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Cookies without Validation and Integrity Checking in a Security Decision', '784');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Path Manipulation Function without Maximum-sized Buffer', '785');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access of Memory Location Before Start of Buffer', '786');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Out-of-bounds Write', '787');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Access of Memory Location After End of Buffer', '788');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Uncontrolled Memory Allocation', '789');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Filtering of Special Elements', '790');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Filtering of Special Elements', '791');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Filtering of One or More Instances of Special Elements', '792');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Only Filtering One Instance of a Special Element', '793');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Incomplete Filtering of Multiple Instances of Special Elements', '794');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Only Filtering Special Elements at a Specified Location', '795');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Only Filtering Special Elements Relative to a Marker', '796');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Only Filtering Special Elements at an Absolute Position', '797');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Use of Hard-coded Credentials', '798');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Improper Control of Interaction Frequency', '799');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Weaknesses in the 2010 CWE/SANS Top 25 Most Dangerous Programming Errors', '800');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2010 Top 25 - Insecure Interaction Between Components', '801');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2010 Top 25 - Risky Resource Management', '802');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2010 Top 25 - Porous Defenses', '803');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Guessable CAPTCHA', '804');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Access with Incorrect Length Value', '805');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Buffer Access Using Size of Source Buffer', '806');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Reliance on Untrusted Inputs in a Security Decision', '807');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('2010 Top 25 - Weaknesses On the Cusp', '808');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Research Concepts', '1000');
INSERT INTO GenericVulnerability (Name, ID) VALUES ('Comprehensive CWE Dictionary', '2000');

SET @generic_vulnerability_location_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Location');
SET @generic_vulnerability_environment_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Environment');
SET @generic_vulnerability_technology_specific_environment_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Technology-specific Environment Issues');
SET @generic_vulnerability_j2ee_environment_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Environment Issues');
SET @generic_vulnerability_j2ee_misconfiguration_data_transmission_without_encryption_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Data Transmission Without Encryption');
SET @generic_vulnerability_j2ee_misconfiguration_insufficient_session_id_length_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Insufficient Session-ID Length');
SET @generic_vulnerability_j2ee_misconfiguration_missing_custom_error_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Missing Custom Error Page');
SET @generic_vulnerability_j2ee_misconfiguration_entity_bean_declared_remote_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Entity Bean Declared Remote');
SET @generic_vulnerability_j2ee_misconfiguration_weak_access_permissions_for_ejb_methods_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods');
SET @generic_vulnerability_asp_net_environment_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Environment Issues');
SET @generic_vulnerability_asp_net_misconfiguration_creating_debug_binary_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Creating Debug Binary');
SET @generic_vulnerability_asp_net_misconfiguration_missing_custom_error_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Missing Custom Error Page');
SET @generic_vulnerability_asp_net_misconfiguration_password_in_configuration_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Password in Configuration File');
SET @generic_vulnerability_compiler_removal_of_code_to_clear_buffers_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Compiler Removal of Code to Clear Buffers');
SET @generic_vulnerability_external_control_of_system_or_configuration_setting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Control of System or Configuration Setting');
SET @generic_vulnerability_configuration_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Configuration');
SET @generic_vulnerability_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Code');
SET @generic_vulnerability_source_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Source Code');
SET @generic_vulnerability_data_handling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Data Handling');
SET @generic_vulnerability_improper_input_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Input Validation');
SET @generic_vulnerability_pathname_traversal_and_equivalence_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Pathname Traversal and Equivalence Errors');
SET @generic_vulnerability_improper_limitation_of_a_pathname_to_a_restricted_directory_path_traversal_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'')');
SET @generic_vulnerability_relative_path_traversal_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Relative Path Traversal');
SET @generic_vulnerability_path_traversal_filedir_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''../filedir''');
SET @generic_vulnerability_path_traversal_filedir_25_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''/../filedir''');
SET @generic_vulnerability_path_traversal_dir_filename_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''/dir/../filename''');
SET @generic_vulnerability_path_traversal_dir_filename_27_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''dir/../../filename''');
SET @generic_vulnerability_path_traversal_filedir_28_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''..\filedir''');
SET @generic_vulnerability_path_traversal_filename_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''\..\filename''');
SET @generic_vulnerability_path_traversal_dir_filename_30_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''\dir\..\filename''');
SET @generic_vulnerability_path_traversal_dir_filename_31_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''dir\..\..\filename''');
SET @generic_vulnerability_path_traversal_triple_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''...'' (Triple Dot)');
SET @generic_vulnerability_path_traversal_multiple_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''....'' (Multiple Dot)');
SET @generic_vulnerability_path_traversal_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''....//''');
SET @generic_vulnerability_path_traversal_35_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''.../...//''');
SET @generic_vulnerability_absolute_path_traversal_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Absolute Path Traversal');
SET @generic_vulnerability_path_traversal_absolute_pathname_here_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''/absolute/pathname/here''');
SET @generic_vulnerability_path_traversal_absolute_pathname_here_38_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''\absolute\pathname\here''');
SET @generic_vulnerability_path_traversal_c_dirname_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''C:dirname''');
SET @generic_vulnerability_path_traversal_unc_share_name_windows_unc_share_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Traversal: ''\\UNC\share\name\'' (Windows UNC Share)');
SET @generic_vulnerability_improper_resolution_of_path_equivalence_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Resolution of Path Equivalence');
SET @generic_vulnerability_path_equivalence_filename_trailing_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filename.'' (Trailing Dot)');
SET @generic_vulnerability_path_equivalence_filename_multiple_trailing_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filename....'' (Multiple Trailing Dot)');
SET @generic_vulnerability_path_equivalence_file_name_internal_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''file.name'' (Internal Dot)');
SET @generic_vulnerability_path_equivalence_file_name_multiple_internal_dot_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''file...name'' (Multiple Internal Dot)');
SET @generic_vulnerability_path_equivalence_filename_trailing_space_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filename '' (Trailing Space)');
SET @generic_vulnerability_path_equivalence_filename_leading_space_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: '' filename (Leading Space)');
SET @generic_vulnerability_path_equivalence_file_name_internal_whitespace_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''file name'' (Internal Whitespace)');
SET @generic_vulnerability_path_equivalence_filename_trailing_slash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filename/'' (Trailing Slash)');
SET @generic_vulnerability_path_equivalence_multiple_leading_slash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''//multiple/leading/slash''');
SET @generic_vulnerability_path_equivalence_multiple_internal_slash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''/multiple//internal/slash''');
SET @generic_vulnerability_path_equivalence_multiple_trailing_slash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''/multiple/trailing/slash//''');
SET @generic_vulnerability_path_equivalence_multiple_internal_backslash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''\multiple\\internal\backslash''');
SET @generic_vulnerability_path_equivalence_filedir_trailing_backslash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filedir\'' (Trailing Backslash)');
SET @generic_vulnerability_path_equivalence_single_dot_directory_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''/./'' (Single Dot Directory)');
SET @generic_vulnerability_path_equivalence_filedir_wildcard_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''filedir*'' (Wildcard)');
SET @generic_vulnerability_path_equivalence_fakedir_realdir_filename_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: ''fakedir/../realdir/filename''');
SET @generic_vulnerability_path_equivalence_windows_8_3_filename_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Path Equivalence: Windows 8.3 Filename');
SET @generic_vulnerability_improper_link_resolution_before_file_access_link_following_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Link Resolution Before File Access (''Link Following'')');
SET @generic_vulnerability_unix_path_link_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UNIX Path Link Problems');
SET @generic_vulnerability_unix_symbolic_link_symlink_following_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UNIX Symbolic Link (Symlink) Following');
SET @generic_vulnerability_unix_hard_link_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UNIX Hard Link');
SET @generic_vulnerability_windows_path_link_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Windows Path Link Problems');
SET @generic_vulnerability_windows_shortcut_following_lnk_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Windows Shortcut Following (.LNK)');
SET @generic_vulnerability_windows_hard_link_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Windows Hard Link');
SET @generic_vulnerability_improper_handling_of_file_names_that_identify_virtual_resources_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of File Names that Identify Virtual Resources');
SET @generic_vulnerability_improper_handling_of_windows_device_names_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Windows Device Names');
SET @generic_vulnerability_windows_virtual_file_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Windows Virtual File Problems');
SET @generic_vulnerability_failure_to_handle_windows_data_alternate_data_stream_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Windows ::DATA Alternate Data Stream');
SET @generic_vulnerability_mac_virtual_file_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Mac Virtual File Problems');
SET @generic_vulnerability_apple_ds_store_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Apple ''.DS_Store''');
SET @generic_vulnerability_improper_handling_of_apple_hfs_alternate_data_stream_path_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Apple HFS+ Alternate Data Stream Path');
SET @generic_vulnerability_external_control_of_file_name_or_path_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Control of File Name or Path');
SET @generic_vulnerability_failure_to_sanitize_data_into_a_different_plane_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data into a Different Plane (''Injection'')');
SET @generic_vulnerability_failure_to_sanitize_special_elements_into_a_different_plane_special_element_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)');
SET @generic_vulnerability_failure_to_resolve_equivalent_special_elements_into_a_different_plane_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Resolve Equivalent Special Elements into a Different Plane');
SET @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements used in a Command (''Command Injection'')');
SET @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_os_command_os_command_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements used in an OS Command (''OS Command Injection'')');
SET @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Preserve Web Page Structure (''Cross-site Scripting'')');
SET @generic_vulnerability_improper_sanitization_of_script_related_html_tags_in_a_web_page_basic_xss_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Script-Related HTML Tags in a Web Page (Basic XSS)');
SET @generic_vulnerability_improper_sanitization_of_script_in_an_error_message_web_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Script in an Error Message Web Page');
SET @generic_vulnerability_improper_sanitization_of_script_in_attributes_of_img_tags_in_a_web_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Script in Attributes of IMG Tags in a Web Page');
SET @generic_vulnerability_failure_to_sanitize_script_in_attributes_in_a_web_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Script in Attributes in a Web Page');
SET @generic_vulnerability_failure_to_resolve_encoded_uri_schemes_in_a_web_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Resolve Encoded URI Schemes in a Web Page');
SET @generic_vulnerability_doubled_character_xss_manipulations_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Doubled Character XSS Manipulations');
SET @generic_vulnerability_failure_to_sanitize_invalid_characters_in_identifiers_in_web_pages_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Invalid Characters in Identifiers in Web Pages');
SET @generic_vulnerability_failure_to_sanitize_alternate_xss_syntax_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Alternate XSS Syntax');
SET @generic_vulnerability_argument_injection_or_modification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Argument Injection or Modification');
SET @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements used in an SQL Command (''SQL Injection'')');
SET @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data into LDAP Queries (''LDAP Injection'')');
SET @generic_vulnerability_xml_injection_aka_blind_xpath_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'XML Injection (aka Blind XPath Injection)');
SET @generic_vulnerability_deprecated_improper_sanitization_of_custom_special_characters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED: Improper Sanitization of Custom Special Characters');
SET @generic_vulnerability_failure_to_sanitize_crlf_sequences_crlf_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize CRLF Sequences (''CRLF Injection'')');
SET @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Control Generation of Code (''Code Injection'')');
SET @generic_vulnerability_improper_sanitization_of_directives_in_dynamically_evaluated_code_eval_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Directives in Dynamically Evaluated Code (''Eval Injection'')');
SET @generic_vulnerability_improper_sanitization_of_directives_in_statically_saved_code_static_code_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Directives in Statically Saved Code (''Static Code Injection'')');
SET @generic_vulnerability_failure_to_sanitize_server_side_includes_ssi_within_a_web_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Server-Side Includes (SSI) Within a Web Page');
SET @generic_vulnerability_improper_control_of_filename_for_include_require_statement_in_php_program_php_file_inclusion_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Control of Filename for Include/Require Statement in PHP Program (''PHP File Inclusion'')');
SET @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Control of Resource Identifiers (''Resource Injection'')');
SET @generic_vulnerability_technology_specific_input_validation_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Technology-Specific Input Validation Problems');
SET @generic_vulnerability_struts_validation_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts Validation Problems');
SET @generic_vulnerability_struts_duplicate_validation_forms_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Duplicate Validation Forms');
SET @generic_vulnerability_struts_incomplete_validate_method_definition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Incomplete validate() Method Definition');
SET @generic_vulnerability_struts_form_bean_does_not_extend_validation_class_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Form Bean Does Not Extend Validation Class');
SET @generic_vulnerability_struts_form_field_without_validator_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Form Field Without Validator');
SET @generic_vulnerability_struts_plug_in_framework_not_in_use_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Plug-in Framework not in Use');
SET @generic_vulnerability_struts_unused_validation_form_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Unused Validation Form');
SET @generic_vulnerability_struts_unvalidated_action_form_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Unvalidated Action Form');
SET @generic_vulnerability_struts_validator_turned_off_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Validator Turned Off');
SET @generic_vulnerability_struts_validator_without_form_field_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Validator Without Form Field');
SET @generic_vulnerability_direct_use_of_unsafe_jni_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Direct Use of Unsafe JNI');
SET @generic_vulnerability_missing_xml_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing XML Validation');
SET @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize CRLF Sequences in HTTP Headers (''HTTP Response Splitting'')');
SET @generic_vulnerability_process_control_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Process Control');
SET @generic_vulnerability_misinterpretation_of_input_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Misinterpretation of Input');
SET @generic_vulnerability_improper_encoding_or_escaping_of_output_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Encoding or Escaping of Output');
SET @generic_vulnerability_improper_output_sanitization_for_logs_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Output Sanitization for Logs');
SET @generic_vulnerability_improper_access_of_indexable_resource_range_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Access of Indexable Resource (''Range Error'')');
SET @generic_vulnerability_failure_to_constrain_operations_within_the_bounds_of_a_memory_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Constrain Operations within the Bounds of a Memory Buffer');
SET @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Copy without Checking Size of Input (''Classic Buffer Overflow'')');
SET @generic_vulnerability_stack_based_buffer_overflow_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Stack-based Buffer Overflow');
SET @generic_vulnerability_heap_based_buffer_overflow_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Heap-based Buffer Overflow');
SET @generic_vulnerability_write_what_where_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Write-what-where Condition');
SET @generic_vulnerability_buffer_underwrite_buffer_underflow_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Underwrite (''Buffer Underflow'')');
SET @generic_vulnerability_out_of_bounds_read_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Out-of-bounds Read');
SET @generic_vulnerability_buffer_over_read_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Over-read');
SET @generic_vulnerability_buffer_under_read_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Under-read');
SET @generic_vulnerability_wrap_around_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Wrap-around Error');
SET @generic_vulnerability_improper_validation_of_array_index_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Validation of Array Index');
SET @generic_vulnerability_improper_handling_of_length_parameter_inconsistency_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Length Parameter Inconsistency ');
SET @generic_vulnerability_incorrect_calculation_of_buffer_size_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Calculation of Buffer Size');
SET @generic_vulnerability_deprecated_duplicate_miscalculated_null_termination_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): Miscalculated Null Termination');
SET @generic_vulnerability_string_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'String Errors');
SET @generic_vulnerability_uncontrolled_format_string_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncontrolled Format String');
SET @generic_vulnerability_incorrect_calculation_of_multi_byte_string_length_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Calculation of Multi-Byte String Length');
SET @generic_vulnerability_type_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Type Errors');
SET @generic_vulnerability_representation_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Representation Errors');
SET @generic_vulnerability_improper_sanitization_of_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Special Elements');
SET @generic_vulnerability_deprecated_general_special_element_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED: General Special Element Problems');
SET @generic_vulnerability_failure_to_sanitize_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Delimiters');
SET @generic_vulnerability_failure_to_sanitize_parameter_argument_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Parameter/Argument Delimiters');
SET @generic_vulnerability_failure_to_sanitize_value_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Value Delimiters');
SET @generic_vulnerability_failure_to_sanitize_record_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Record Delimiters');
SET @generic_vulnerability_failure_to_sanitize_line_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Line Delimiters');
SET @generic_vulnerability_failure_to_sanitize_section_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Section Delimiters');
SET @generic_vulnerability_failure_to_sanitize_expression_command_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Expression/Command Delimiters');
SET @generic_vulnerability_improper_sanitization_of_input_terminators_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Input Terminators');
SET @generic_vulnerability_failure_to_sanitize_input_leaders_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Input Leaders');
SET @generic_vulnerability_failure_to_sanitize_quoting_syntax_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Quoting Syntax');
SET @generic_vulnerability_failure_to_sanitize_escape_meta_or_control_sequences_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Escape, Meta, or Control Sequences');
SET @generic_vulnerability_improper_sanitization_of_comment_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Comment Delimiters');
SET @generic_vulnerability_improper_sanitization_of_macro_symbols_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Macro Symbols');
SET @generic_vulnerability_improper_sanitization_of_substitution_characters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Substitution Characters');
SET @generic_vulnerability_improper_sanitization_of_variable_name_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Variable Name Delimiters');
SET @generic_vulnerability_improper_sanitization_of_wildcards_or_matching_symbols_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Wildcards or Matching Symbols');
SET @generic_vulnerability_improper_sanitization_of_whitespace_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Whitespace');
SET @generic_vulnerability_failure_to_sanitize_paired_delimiters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Paired Delimiters');
SET @generic_vulnerability_failure_to_sanitize_null_byte_or_nul_character_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Null Byte or NUL Character');
SET @generic_vulnerability_failure_to_sanitize_special_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Special Element');
SET @generic_vulnerability_improper_sanitization_of_leading_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Leading Special Elements');
SET @generic_vulnerability_improper_sanitization_of_multiple_leading_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Multiple Leading Special Elements');
SET @generic_vulnerability_improper_sanitization_of_trailing_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Trailing Special Elements');
SET @generic_vulnerability_improper_sanitization_of_multiple_trailing_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Multiple Trailing Special Elements');
SET @generic_vulnerability_improper_sanitization_of_internal_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Internal Special Elements');
SET @generic_vulnerability_improper_sanitization_of_multiple_internal_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of Multiple Internal Special Elements');
SET @generic_vulnerability_improper_handling_of_missing_special_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Missing Special Element');
SET @generic_vulnerability_improper_handling_of_additional_special_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Additional Special Element');
SET @generic_vulnerability_failure_to_resolve_inconsistent_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Resolve Inconsistent Special Elements');
SET @generic_vulnerability_technology_specific_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Technology-Specific Special Elements');
SET @generic_vulnerability_improper_null_termination_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Null Termination');
SET @generic_vulnerability_cleansing_canonicalization_and_comparison_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cleansing, Canonicalization, and Comparison Errors');
SET @generic_vulnerability_encoding_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Encoding Error');
SET @generic_vulnerability_failure_to_handle_alternate_encoding_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Alternate Encoding');
SET @generic_vulnerability_double_decoding_of_the_same_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Double Decoding of the Same Data');
SET @generic_vulnerability_failure_to_handle_mixed_encoding_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Mixed Encoding');
SET @generic_vulnerability_failure_to_handle_unicode_encoding_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Unicode Encoding');
SET @generic_vulnerability_failure_to_handle_url_encoding_hex_encoding_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle URL Encoding (Hex Encoding)');
SET @generic_vulnerability_failure_to_resolve_case_sensitivity_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Resolve Case Sensitivity');
SET @generic_vulnerability_incorrect_behavior_order_early_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Early Validation');
SET @generic_vulnerability_incorrect_behavior_order_validate_before_canonicalize_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Validate Before Canonicalize');
SET @generic_vulnerability_incorrect_behavior_order_validate_before_filter_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Validate Before Filter');
SET @generic_vulnerability_collapse_of_data_into_unsafe_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Collapse of Data Into Unsafe Value');
SET @generic_vulnerability_permissive_whitelist_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Permissive Whitelist');
SET @generic_vulnerability_incomplete_blacklist_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Blacklist');
SET @generic_vulnerability_incorrect_regular_expression_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Regular Expression');
SET @generic_vulnerability_overly_restrictive_regular_expression_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Overly Restrictive Regular Expression');
SET @generic_vulnerability_partial_comparison_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Partial Comparison');
SET @generic_vulnerability_reliance_on_data_memory_layout_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Data/Memory Layout');
SET @generic_vulnerability_numeric_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Numeric Errors');
SET @generic_vulnerability_integer_overflow_or_wraparound_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Integer Overflow or Wraparound');
SET @generic_vulnerability_integer_underflow_wrap_or_wraparound_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Integer Underflow (Wrap or Wraparound)');
SET @generic_vulnerability_integer_coercion_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Integer Coercion Error');
SET @generic_vulnerability_off_by_one_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Off-by-one Error');
SET @generic_vulnerability_unexpected_sign_extension_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unexpected Sign Extension');
SET @generic_vulnerability_signed_to_unsigned_conversion_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Signed to Unsigned Conversion Error');
SET @generic_vulnerability_unsigned_to_signed_conversion_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unsigned to Signed Conversion Error');
SET @generic_vulnerability_numeric_truncation_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Numeric Truncation Error');
SET @generic_vulnerability_use_of_incorrect_byte_ordering_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Incorrect Byte Ordering');
SET @generic_vulnerability_information_management_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Management Errors');
SET @generic_vulnerability_information_exposure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure');
SET @generic_vulnerability_information_leak_through_sent_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Sent Data');
SET @generic_vulnerability_privacy_leak_through_data_queries_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privacy Leak through Data Queries');
SET @generic_vulnerability_information_exposure_through_discrepancy_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure Through Discrepancy');
SET @generic_vulnerability_response_discrepancy_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Response Discrepancy Information Leak');
SET @generic_vulnerability_information_exposure_through_behavioral_discrepancy_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure Through Behavioral Discrepancy');
SET @generic_vulnerability_internal_behavioral_inconsistency_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Internal Behavioral Inconsistency Information Leak');
SET @generic_vulnerability_information_exposure_through_an_external_behavioral_inconsistency_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure Through an External Behavioral Inconsistency');
SET @generic_vulnerability_timing_discrepancy_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Timing Discrepancy Information Leak');
SET @generic_vulnerability_information_exposure_through_an_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Exposure Through an Error Message');
SET @generic_vulnerability_product_generated_error_message_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Product-Generated Error Message Information Leak');
SET @generic_vulnerability_product_external_error_message_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Product-External Error Message Information Leak');
SET @generic_vulnerability_improper_cross_boundary_removal_of_sensitive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Cross-boundary Removal of Sensitive Data');
SET @generic_vulnerability_intended_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Intended Information Leak');
SET @generic_vulnerability_process_environment_information_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Process Environment Information Leak');
SET @generic_vulnerability_information_leak_through_debug_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Debug Information');
SET @generic_vulnerability_containment_errors_container_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Containment Errors (Container Errors)');
SET @generic_vulnerability_deprecated_failure_to_protect_stored_data_from_modification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED: Failure to Protect Stored Data from Modification');
SET @generic_vulnerability_deprecated_duplicate_failure_to_provide_confidentiality_for_stored_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): Failure to provide confidentiality for stored data');
SET @generic_vulnerability_sensitive_data_under_web_root_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Sensitive Data Under Web Root');
SET @generic_vulnerability_sensitive_data_under_ftp_root_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Sensitive Data Under FTP Root');
SET @generic_vulnerability_information_loss_or_omission_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Loss or Omission');
SET @generic_vulnerability_truncation_of_security_relevant_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Truncation of Security-relevant Information');
SET @generic_vulnerability_omission_of_security_relevant_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Omission of Security-relevant Information');
SET @generic_vulnerability_obscured_security_relevant_information_by_alternate_name_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Obscured Security-relevant Information by Alternate Name');
SET @generic_vulnerability_deprecated_duplicate_general_information_management_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): General Information Management Problems');
SET @generic_vulnerability_sensitive_information_uncleared_before_release_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Sensitive Information Uncleared Before Release');
SET @generic_vulnerability_failure_to_fulfill_api_contract_api_abuse_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Fulfill API Contract (''API Abuse'')');
SET @generic_vulnerability_improper_handling_of_syntactically_invalid_structure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Syntactically Invalid Structure');
SET @generic_vulnerability_improper_handling_of_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Values');
SET @generic_vulnerability_improper_handling_of_missing_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Missing Values');
SET @generic_vulnerability_improper_handling_of_extra_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Extra Values');
SET @generic_vulnerability_improper_handling_of_undefined_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Undefined Values');
SET @generic_vulnerability_parameter_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Parameter Problems');
SET @generic_vulnerability_failure_to_handle_missing_parameter_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Missing Parameter');
SET @generic_vulnerability_improper_handling_of_extra_parameters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Extra Parameters');
SET @generic_vulnerability_improper_handling_of_undefined_parameters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Undefined Parameters');
SET @generic_vulnerability_improper_handling_of_structural_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Structural Elements');
SET @generic_vulnerability_improper_handling_of_incomplete_structural_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Incomplete Structural Elements');
SET @generic_vulnerability_failure_to_handle_incomplete_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Incomplete Element');
SET @generic_vulnerability_improper_handling_of_inconsistent_structural_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Inconsistent Structural Elements');
SET @generic_vulnerability_improper_handling_of_unexpected_data_type_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Unexpected Data Type');
SET @generic_vulnerability_use_of_inherently_dangerous_function_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Inherently Dangerous Function');
SET @generic_vulnerability_failure_to_change_working_directory_in_chroot_jail_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Change Working Directory in chroot Jail');
SET @generic_vulnerability_failure_to_clear_heap_memory_before_release_heap_inspection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Clear Heap Memory Before Release (''Heap Inspection'')');
SET @generic_vulnerability_j2ee_bad_practices_direct_management_of_connections_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Bad Practices: Direct Management of Connections');
SET @generic_vulnerability_j2ee_bad_practices_direct_use_of_sockets_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Bad Practices: Direct Use of Sockets');
SET @generic_vulnerability_reliance_on_dns_lookups_in_a_security_decision_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on DNS Lookups in a Security Decision');
SET @generic_vulnerability_uncaught_exception_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncaught Exception');
SET @generic_vulnerability_deprecated_often_misused_path_manipulation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED: Often Misused: Path Manipulation');
SET @generic_vulnerability_execution_with_unnecessary_privileges_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Execution with Unnecessary Privileges');
SET @generic_vulnerability_often_misused_string_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Often Misused: String Management');
SET @generic_vulnerability_unchecked_return_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unchecked Return Value');
SET @generic_vulnerability_incorrect_check_of_function_return_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Check of Function Return Value');
SET @generic_vulnerability_security_features_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Security Features');
SET @generic_vulnerability_credentials_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Credentials Management');
SET @generic_vulnerability_plaintext_storage_of_a_password_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage of a Password');
SET @generic_vulnerability_storing_passwords_in_a_recoverable_format_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Storing Passwords in a Recoverable Format');
SET @generic_vulnerability_empty_password_in_configuration_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Empty Password in Configuration File');
SET @generic_vulnerability_use_of_hard_coded_password_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Hard-coded Password');
SET @generic_vulnerability_password_in_configuration_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Password in Configuration File');
SET @generic_vulnerability_weak_cryptography_for_passwords_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weak Cryptography for Passwords');
SET @generic_vulnerability_not_using_password_aging_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Not Using Password Aging');
SET @generic_vulnerability_password_aging_with_long_expiration_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Password Aging with Long Expiration');
SET @generic_vulnerability_permissions_privileges_and_access_controls_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Permissions, Privileges, and Access Controls');
SET @generic_vulnerability_privilege_sandbox_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privilege / Sandbox Issues');
SET @generic_vulnerability_incorrect_privilege_assignment_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Privilege Assignment');
SET @generic_vulnerability_privilege_defined_with_unsafe_actions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privilege Defined With Unsafe Actions');
SET @generic_vulnerability_privilege_chaining_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privilege Chaining');
SET @generic_vulnerability_improper_privilege_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Privilege Management');
SET @generic_vulnerability_privilege_context_switching_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privilege Context Switching Error');
SET @generic_vulnerability_privilege_dropping_lowering_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privilege Dropping / Lowering Errors');
SET @generic_vulnerability_least_privilege_violation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Least Privilege Violation');
SET @generic_vulnerability_improper_check_for_dropped_privileges_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Check for Dropped Privileges');
SET @generic_vulnerability_improper_handling_of_insufficient_privileges_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Insufficient Privileges');
SET @generic_vulnerability_permission_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Permission Issues');
SET @generic_vulnerability_incorrect_default_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Default Permissions');
SET @generic_vulnerability_insecure_inherited_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insecure Inherited Permissions');
SET @generic_vulnerability_insecure_preserved_inherited_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insecure Preserved Inherited Permissions');
SET @generic_vulnerability_incorrect_execution_assigned_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Execution-Assigned Permissions');
SET @generic_vulnerability_improper_handling_of_insufficient_permissions_or_privileges_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Insufficient Permissions or Privileges ');
SET @generic_vulnerability_improper_preservation_of_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Preservation of Permissions');
SET @generic_vulnerability_improper_ownership_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Ownership Management');
SET @generic_vulnerability_unverified_ownership_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unverified Ownership');
SET @generic_vulnerability_access_control_authorization_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access Control (Authorization) Issues');
SET @generic_vulnerability_improper_access_control_authorization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Access Control (Authorization)');
SET @generic_vulnerability_incorrect_user_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect User Management');
SET @generic_vulnerability_improper_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Authentication');
SET @generic_vulnerability_authentication_bypass_using_an_alternate_path_or_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass Using an Alternate Path or Channel');
SET @generic_vulnerability_authentication_bypass_by_alternate_name_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass by Alternate Name');
SET @generic_vulnerability_authentication_bypass_by_spoofing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass by Spoofing');
SET @generic_vulnerability_trusting_self_reported_ip_address_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trusting Self-reported IP Address');
SET @generic_vulnerability_trusting_self_reported_dns_name_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trusting Self-reported DNS Name');
SET @generic_vulnerability_using_referer_field_for_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Using Referer Field for Authentication');
SET @generic_vulnerability_authentication_bypass_by_capture_replay_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass by Capture-replay');
SET @generic_vulnerability_certificate_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Certificate Issues');
SET @generic_vulnerability_improper_following_of_chain_of_trust_for_certificate_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Following of Chain of Trust for Certificate Validation');
SET @generic_vulnerability_improper_validation_of_host_specific_certificate_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Validation of Host-specific Certificate Data');
SET @generic_vulnerability_improper_validation_of_certificate_expiration_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Validation of Certificate Expiration');
SET @generic_vulnerability_improper_check_for_certificate_revocation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Check for Certificate Revocation');
SET @generic_vulnerability_channel_accessible_by_non_endpoint_man_in_the_middle_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Channel Accessible by Non-Endpoint (''Man-in-the-Middle'')');
SET @generic_vulnerability_reflection_attack_in_an_authentication_protocol_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reflection Attack in an Authentication Protocol');
SET @generic_vulnerability_authentication_bypass_by_assumed_immutable_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass by Assumed-Immutable Data');
SET @generic_vulnerability_incorrect_implementation_of_authentication_algorithm_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Implementation of Authentication Algorithm');
SET @generic_vulnerability_missing_critical_step_in_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Critical Step in Authentication');
SET @generic_vulnerability_authentication_bypass_by_primary_weakness_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass by Primary Weakness');
SET @generic_vulnerability_missing_authentication_for_critical_function_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Authentication for Critical Function');
SET @generic_vulnerability_improper_restriction_of_excessive_authentication_attempts_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Restriction of Excessive Authentication Attempts');
SET @generic_vulnerability_use_of_single_factor_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Single-factor Authentication');
SET @generic_vulnerability_use_of_password_system_for_primary_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Password System for Primary Authentication');
SET @generic_vulnerability_cryptographic_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cryptographic Issues');
SET @generic_vulnerability_missing_encryption_of_sensitive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Encryption of Sensitive Data');
SET @generic_vulnerability_cleartext_storage_of_sensitive_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cleartext Storage of Sensitive Information');
SET @generic_vulnerability_plaintext_storage_in_a_file_or_on_disk_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in a File or on Disk');
SET @generic_vulnerability_plaintext_storage_in_the_registry_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in the Registry');
SET @generic_vulnerability_plaintext_storage_in_a_cookie_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in a Cookie');
SET @generic_vulnerability_plaintext_storage_in_memory_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in Memory');
SET @generic_vulnerability_plaintext_storage_in_gui_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in GUI');
SET @generic_vulnerability_plaintext_storage_in_executable_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Plaintext Storage in Executable');
SET @generic_vulnerability_cleartext_transmission_of_sensitive_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cleartext Transmission of Sensitive Information');
SET @generic_vulnerability_key_management_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Key Management Errors');
SET @generic_vulnerability_use_of_hard_coded_cryptographic_key_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Hard-coded Cryptographic Key');
SET @generic_vulnerability_key_exchange_without_entity_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Key Exchange without Entity Authentication');
SET @generic_vulnerability_reusing_a_nonce_key_pair_in_encryption_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reusing a Nonce, Key Pair in Encryption');
SET @generic_vulnerability_use_of_a_key_past_its_expiration_date_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of a Key Past its Expiration Date');
SET @generic_vulnerability_missing_required_cryptographic_step_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Required Cryptographic Step');
SET @generic_vulnerability_inadequate_encryption_strength_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Inadequate Encryption Strength');
SET @generic_vulnerability_use_of_a_broken_or_risky_cryptographic_algorithm_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of a Broken or Risky Cryptographic Algorithm');
SET @generic_vulnerability_reversible_one_way_hash_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reversible One-Way Hash');
SET @generic_vulnerability_not_using_a_random_iv_with_cbc_mode_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Not Using a Random IV with CBC Mode');
SET @generic_vulnerability_use_of_insufficiently_random_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Insufficiently Random Values');
SET @generic_vulnerability_insufficient_entropy_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Entropy');
SET @generic_vulnerability_insufficient_entropy_in_prng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Entropy in PRNG');
SET @generic_vulnerability_improper_handling_of_insufficient_entropy_in_trng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Insufficient Entropy in TRNG');
SET @generic_vulnerability_small_space_of_random_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Small Space of Random Values');
SET @generic_vulnerability_prng_seed_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'PRNG Seed Error');
SET @generic_vulnerability_same_seed_in_prng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Same Seed in PRNG');
SET @generic_vulnerability_predictable_seed_in_prng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Predictable Seed in PRNG');
SET @generic_vulnerability_use_of_cryptographically_weak_prng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Cryptographically Weak PRNG');
SET @generic_vulnerability_small_seed_space_in_prng_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Small Seed Space in PRNG');
SET @generic_vulnerability_predictability_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Predictability Problems');
SET @generic_vulnerability_predictable_from_observable_state_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Predictable from Observable State');
SET @generic_vulnerability_predictable_exact_value_from_previous_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Predictable Exact Value from Previous Values');
SET @generic_vulnerability_predictable_value_range_from_previous_values_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Predictable Value Range from Previous Values');
SET @generic_vulnerability_use_of_invariant_value_in_dynamically_changing_context_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Invariant Value in Dynamically Changing Context');
SET @generic_vulnerability_insufficient_verification_of_data_authenticity_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Verification of Data Authenticity');
SET @generic_vulnerability_origin_validation_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Origin Validation Error');
SET @generic_vulnerability_improper_verification_of_cryptographic_signature_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Verification of Cryptographic Signature');
SET @generic_vulnerability_use_of_less_trusted_source_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Less Trusted Source');
SET @generic_vulnerability_acceptance_of_extraneous_untrusted_data_with_trusted_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Acceptance of Extraneous Untrusted Data With Trusted Data');
SET @generic_vulnerability_improperly_trusted_reverse_dns_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improperly Trusted Reverse DNS');
SET @generic_vulnerability_insufficient_type_distinction_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Type Distinction');
SET @generic_vulnerability_cross_site_request_forgery_csrf_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Cross-Site Request Forgery (CSRF)');
SET @generic_vulnerability_failure_to_add_integrity_check_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Add Integrity Check Value');
SET @generic_vulnerability_improper_validation_of_integrity_check_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Validation of Integrity Check Value');
SET @generic_vulnerability_user_interface_security_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'User Interface Security Issues');
SET @generic_vulnerability_product_ui_does_not_warn_user_of_unsafe_actions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Product UI does not Warn User of Unsafe Actions');
SET @generic_vulnerability_insufficient_ui_warning_of_dangerous_operations_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient UI Warning of Dangerous Operations');
SET @generic_vulnerability_improperly_implemented_security_check_for_standard_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improperly Implemented Security Check for Standard');
SET @generic_vulnerability_privacy_violation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Privacy Violation');
SET @generic_vulnerability_trust_of_system_event_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trust of System Event Data');
SET @generic_vulnerability_time_and_state_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Time and State');
SET @generic_vulnerability_race_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Race Condition');
SET @generic_vulnerability_race_condition_enabling_link_following_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Race Condition Enabling Link Following');
SET @generic_vulnerability_signal_handler_race_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Signal Handler Race Condition');
SET @generic_vulnerability_race_condition_in_switch_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Race Condition in Switch');
SET @generic_vulnerability_race_condition_within_a_thread_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Race Condition within a Thread');
SET @generic_vulnerability_time_of_check_time_of_use_toctou_race_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Time-of-check Time-of-use (TOCTOU) Race Condition');
SET @generic_vulnerability_context_switching_race_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Context Switching Race Condition');
SET @generic_vulnerability_divide_by_zero_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Divide By Zero');
SET @generic_vulnerability_missing_check_for_certificate_revocation_after_initial_check_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Check for Certificate Revocation after Initial Check');
SET @generic_vulnerability_state_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'State Issues');
SET @generic_vulnerability_incomplete_internal_state_distinction_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Internal State Distinction');
SET @generic_vulnerability_state_synchronization_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'State Synchronization Error');
SET @generic_vulnerability_mutable_objects_passed_by_reference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Mutable Objects Passed by Reference');
SET @generic_vulnerability_passing_mutable_objects_to_an_untrusted_method_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Passing Mutable Objects to an Untrusted Method');
SET @generic_vulnerability_temporary_file_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Temporary File Issues');
SET @generic_vulnerability_insecure_temporary_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insecure Temporary File');
SET @generic_vulnerability_creation_of_temporary_file_with_insecure_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Creation of Temporary File With Insecure Permissions');
SET @generic_vulnerability_creation_of_temporary_file_in_directory_with_incorrect_permissions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Creation of Temporary File in Directory with Incorrect Permissions');
SET @generic_vulnerability_technology_specific_time_and_state_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Technology-Specific Time and State Issues');
SET @generic_vulnerability_j2ee_time_and_state_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Time and State Issues');
SET @generic_vulnerability_j2ee_bad_practices_use_of_system_exit_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Bad Practices: Use of System.exit()');
SET @generic_vulnerability_j2ee_bad_practices_direct_use_of_threads_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Bad Practices: Direct Use of Threads');
SET @generic_vulnerability_session_fixation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Session Fixation');
SET @generic_vulnerability_covert_timing_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Covert Timing Channel');
SET @generic_vulnerability_symbolic_name_not_mapping_to_correct_object_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Symbolic Name not Mapping to Correct Object');
SET @generic_vulnerability_signal_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Signal Errors');
SET @generic_vulnerability_error_handling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Error Handling');
SET @generic_vulnerability_error_conditions_return_values_status_codes_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Error Conditions, Return Values, Status Codes');
SET @generic_vulnerability_detection_of_error_condition_without_action_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Detection of Error Condition Without Action');
SET @generic_vulnerability_unchecked_error_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unchecked Error Condition');
SET @generic_vulnerability_failure_to_report_error_in_status_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Report Error in Status Code');
SET @generic_vulnerability_return_of_wrong_status_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Return of Wrong Status Code');
SET @generic_vulnerability_unexpected_status_code_or_return_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unexpected Status Code or Return Value');
SET @generic_vulnerability_use_of_nullpointerexception_catch_to_detect_null_pointer_dereference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of NullPointerException Catch to Detect NULL Pointer Dereference');
SET @generic_vulnerability_declaration_of_catch_for_generic_exception_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Declaration of Catch for Generic Exception');
SET @generic_vulnerability_declaration_of_throws_for_generic_exception_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Declaration of Throws for Generic Exception');
SET @generic_vulnerability_indicator_of_poor_code_quality_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Indicator of Poor Code Quality');
SET @generic_vulnerability_resource_management_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Resource Management Errors');
SET @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncontrolled Resource Consumption (''Resource Exhaustion'')');
SET @generic_vulnerability_failure_to_release_memory_before_removing_last_reference_memory_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Release Memory Before Removing Last Reference (''Memory Leak'')');
SET @generic_vulnerability_transmission_of_private_resources_into_a_new_sphere_resource_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Transmission of Private Resources into a New Sphere (''Resource Leak'')');
SET @generic_vulnerability_unix_file_descriptor_leak_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UNIX File Descriptor Leak');
SET @generic_vulnerability_improper_resource_shutdown_or_release_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Resource Shutdown or Release');
SET @generic_vulnerability_asymmetric_resource_consumption_amplification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Asymmetric Resource Consumption (Amplification)');
SET @generic_vulnerability_insufficient_control_of_network_message_volume_network_amplification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Control of Network Message Volume (Network Amplification)');
SET @generic_vulnerability_algorithmic_complexity_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Algorithmic Complexity');
SET @generic_vulnerability_incorrect_behavior_order_early_amplification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Early Amplification');
SET @generic_vulnerability_improper_handling_of_highly_compressed_data_data_amplification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Highly Compressed Data (Data Amplification)');
SET @generic_vulnerability_insufficient_resource_pool_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Resource Pool');
SET @generic_vulnerability_resource_locking_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Resource Locking Problems');
SET @generic_vulnerability_unrestricted_externally_accessible_lock_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unrestricted Externally Accessible Lock');
SET @generic_vulnerability_insufficient_resource_locking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Resource Locking');
SET @generic_vulnerability_missing_lock_check_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Lock Check');
SET @generic_vulnerability_double_free_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Double Free');
SET @generic_vulnerability_use_after_free_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use After Free');
SET @generic_vulnerability_channel_and_path_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Channel and Path Errors');
SET @generic_vulnerability_channel_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Channel Errors');
SET @generic_vulnerability_unprotected_primary_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unprotected Primary Channel');
SET @generic_vulnerability_unprotected_alternate_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unprotected Alternate Channel');
SET @generic_vulnerability_race_condition_during_access_to_alternate_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Race Condition During Access to Alternate Channel');
SET @generic_vulnerability_unprotected_windows_messaging_channel_shatter_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unprotected Windows Messaging Channel (''Shatter'')');
SET @generic_vulnerability_deprecated_duplicate_proxied_trusted_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): Proxied Trusted Channel');
SET @generic_vulnerability_failure_to_protect_alternate_path_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Protect Alternate Path');
SET @generic_vulnerability_direct_request_forced_browsing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Direct Request (''Forced Browsing'')');
SET @generic_vulnerability_untrusted_search_path_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Untrusted Search Path');
SET @generic_vulnerability_uncontrolled_search_path_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncontrolled Search Path Element');
SET @generic_vulnerability_unquoted_search_path_or_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unquoted Search Path or Element');
SET @generic_vulnerability_handler_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Handler Errors');
SET @generic_vulnerability_deployment_of_wrong_handler_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Deployment of Wrong Handler');
SET @generic_vulnerability_missing_handler_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Handler');
SET @generic_vulnerability_dangerous_handler_not_disabled_during_sensitive_operations_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Dangerous Handler not Disabled During Sensitive Operations');
SET @generic_vulnerability_unparsed_raw_web_content_delivery_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unparsed Raw Web Content Delivery');
SET @generic_vulnerability_unrestricted_upload_of_file_with_dangerous_type_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unrestricted Upload of File with Dangerous Type');
SET @generic_vulnerability_interaction_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Interaction Error');
SET @generic_vulnerability_interpretation_conflict_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Interpretation Conflict');
SET @generic_vulnerability_incomplete_model_of_endpoint_features_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Model of Endpoint Features');
SET @generic_vulnerability_behavioral_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Behavioral Problems');
SET @generic_vulnerability_behavioral_change_in_new_version_or_environment_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Behavioral Change in New Version or Environment');
SET @generic_vulnerability_expected_behavior_violation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Expected Behavior Violation');
SET @generic_vulnerability_unintended_proxy_intermediary_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unintended Proxy/Intermediary');
SET @generic_vulnerability_web_problems_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Web Problems');
SET @generic_vulnerability_deprecated_duplicate_http_response_splitting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): HTTP response splitting');
SET @generic_vulnerability_inconsistent_interpretation_of_http_requests_http_request_smuggling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Inconsistent Interpretation of HTTP Requests (''HTTP Request Smuggling'')');
SET @generic_vulnerability_user_interface_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'User Interface Errors');
SET @generic_vulnerability_ui_discrepancy_for_security_feature_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UI Discrepancy for Security Feature');
SET @generic_vulnerability_unimplemented_or_unsupported_feature_in_ui_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unimplemented or Unsupported Feature in UI');
SET @generic_vulnerability_obsolete_feature_in_ui_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Obsolete Feature in UI');
SET @generic_vulnerability_the_ui_performs_the_wrong_action_id := (SELECT id FROM GenericVulnerability WHERE Name = 'The UI Performs the Wrong Action');
SET @generic_vulnerability_multiple_interpretations_of_ui_input_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Multiple Interpretations of UI Input');
SET @generic_vulnerability_ui_misrepresentation_of_critical_information_id := (SELECT id FROM GenericVulnerability WHERE Name = 'UI Misrepresentation of Critical Information');
SET @generic_vulnerability_initialization_and_cleanup_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Initialization and Cleanup Errors');
SET @generic_vulnerability_insecure_default_variable_initialization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insecure Default Variable Initialization');
SET @generic_vulnerability_external_initialization_of_trusted_variables_or_data_stores_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Initialization of Trusted Variables or Data Stores');
SET @generic_vulnerability_non_exit_on_failed_initialization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Non-exit on Failed Initialization');
SET @generic_vulnerability_missing_initialization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Initialization');
SET @generic_vulnerability_use_of_uninitialized_variable_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Uninitialized Variable');
SET @generic_vulnerability_deprecated_incorrect_initialization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED: Incorrect Initialization');
SET @generic_vulnerability_incomplete_cleanup_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Cleanup');
SET @generic_vulnerability_improper_cleanup_on_thrown_exception_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Cleanup on Thrown Exception');
SET @generic_vulnerability_data_structure_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Data Structure Issues');
SET @generic_vulnerability_duplicate_key_in_associative_list_alist_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Duplicate Key in Associative List (Alist)');
SET @generic_vulnerability_deletion_of_data_structure_sentinel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Deletion of Data Structure Sentinel');
SET @generic_vulnerability_addition_of_data_structure_sentinel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Addition of Data Structure Sentinel');
SET @generic_vulnerability_pointer_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Pointer Issues');
SET @generic_vulnerability_return_of_pointer_value_outside_of_expected_range_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Return of Pointer Value Outside of Expected Range');
SET @generic_vulnerability_use_of_sizeof_on_a_pointer_type_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of sizeof() on a Pointer Type');
SET @generic_vulnerability_incorrect_pointer_scaling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Pointer Scaling');
SET @generic_vulnerability_use_of_pointer_subtraction_to_determine_size_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Pointer Subtraction to Determine Size');
SET @generic_vulnerability_use_of_externally_controlled_input_to_select_classes_or_code_unsafe_reflection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Externally-Controlled Input to Select Classes or Code (''Unsafe Reflection'')');
SET @generic_vulnerability_modification_of_assumed_immutable_data_maid_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Modification of Assumed-Immutable Data (MAID)');
SET @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Control of Assumed-Immutable Web Parameter');
SET @generic_vulnerability_php_external_variable_modification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'PHP External Variable Modification');
SET @generic_vulnerability_use_of_function_with_inconsistent_implementations_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Function with Inconsistent Implementations');
SET @generic_vulnerability_undefined_behavior_for_input_to_api_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Undefined Behavior for Input to API');
SET @generic_vulnerability_null_pointer_dereference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'NULL Pointer Dereference');
SET @generic_vulnerability_use_of_obsolete_functions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Obsolete Functions');
SET @generic_vulnerability_missing_default_case_in_switch_statement_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Default Case in Switch Statement');
SET @generic_vulnerability_unsafe_function_call_from_a_signal_handler_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unsafe Function Call from a Signal Handler');
SET @generic_vulnerability_use_of_incorrect_operator_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Incorrect Operator');
SET @generic_vulnerability_assigning_instead_of_comparing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Assigning instead of Comparing');
SET @generic_vulnerability_comparing_instead_of_assigning_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Comparing instead of Assigning');
SET @generic_vulnerability_incorrect_block_delimitation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Block Delimitation');
SET @generic_vulnerability_omitted_break_statement_in_switch_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Omitted Break Statement in Switch');
SET @generic_vulnerability_insufficient_encapsulation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Encapsulation');
SET @generic_vulnerability_comparison_of_classes_by_name_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Comparison of Classes by Name');
SET @generic_vulnerability_reliance_on_package_level_scope_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Package-level Scope');
SET @generic_vulnerability_data_leak_between_sessions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Data Leak Between Sessions');
SET @generic_vulnerability_leftover_debug_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Leftover Debug Code');
SET @generic_vulnerability_mobile_code_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Mobile Code Issues');
SET @generic_vulnerability_public_cloneable_method_without_final_object_hijack_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Public cloneable() Method Without Final (''Object Hijack'')');
SET @generic_vulnerability_use_of_inner_class_containing_sensitive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Inner Class Containing Sensitive Data');
SET @generic_vulnerability_critical_public_variable_without_final_modifier_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Critical Public Variable Without Final Modifier');
SET @generic_vulnerability_download_of_code_without_integrity_check_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Download of Code Without Integrity Check');
SET @generic_vulnerability_private_array_typed_field_returned_from_a_public_method_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Private Array-Typed Field Returned From A Public Method');
SET @generic_vulnerability_public_data_assigned_to_private_array_typed_field_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Public Data Assigned to Private Array-Typed Field');
SET @generic_vulnerability_exposure_of_system_data_to_an_unauthorized_control_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of System Data to an Unauthorized Control Sphere');
SET @generic_vulnerability_information_leak_through_class_cloning_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak through Class Cloning');
SET @generic_vulnerability_serializable_class_containing_sensitive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Serializable Class Containing Sensitive Data');
SET @generic_vulnerability_public_static_field_not_marked_final_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Public Static Field Not Marked Final');
SET @generic_vulnerability_trust_boundary_violation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trust Boundary Violation');
SET @generic_vulnerability_deserialization_of_untrusted_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Deserialization of Untrusted Data');
SET @generic_vulnerability_byte_object_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Byte/Object Code');
SET @generic_vulnerability_motivation_intent_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Motivation/Intent');
SET @generic_vulnerability_intentionally_introduced_weakness_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Intentionally Introduced Weakness');
SET @generic_vulnerability_embedded_malicious_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Embedded Malicious Code');
SET @generic_vulnerability_trojan_horse_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trojan Horse');
SET @generic_vulnerability_non_replicating_malicious_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Non-Replicating Malicious Code');
SET @generic_vulnerability_replicating_malicious_code_virus_or_worm_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Replicating Malicious Code (Virus or Worm)');
SET @generic_vulnerability_trapdoor_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trapdoor');
SET @generic_vulnerability_logic_time_bomb_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Logic/Time Bomb');
SET @generic_vulnerability_spyware_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Spyware');
SET @generic_vulnerability_intentionally_introduced_nonmalicious_weakness_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Intentionally Introduced Nonmalicious Weakness');
SET @generic_vulnerability_covert_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Covert Channel');
SET @generic_vulnerability_covert_storage_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Covert Storage Channel');
SET @generic_vulnerability_deprecated_duplicate_covert_timing_channel_id := (SELECT id FROM GenericVulnerability WHERE Name = 'DEPRECATED (Duplicate): Covert Timing Channel');
SET @generic_vulnerability_other_intentional_nonmalicious_weakness_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Other Intentional, Nonmalicious Weakness');
SET @generic_vulnerability_inadvertently_introduced_weakness_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Inadvertently Introduced Weakness');
SET @generic_vulnerability__net_environment_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = '.NET Environment Issues');
SET @generic_vulnerability__net_misconfiguration_use_of_impersonation_id := (SELECT id FROM GenericVulnerability WHERE Name = '.NET Misconfiguration: Use of Impersonation');
SET @generic_vulnerability_weak_password_requirements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weak Password Requirements');
SET @generic_vulnerability_insufficiently_protected_credentials_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficiently Protected Credentials');
SET @generic_vulnerability_unprotected_transport_of_credentials_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unprotected Transport of Credentials');
SET @generic_vulnerability_information_leak_through_caching_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Caching');
SET @generic_vulnerability_information_leak_through_browser_caching_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Browser Caching');
SET @generic_vulnerability_information_leak_through_environmental_variables_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Environmental Variables');
SET @generic_vulnerability_exposure_of_cvs_repository_to_an_unauthorized_control_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of CVS Repository to an Unauthorized Control Sphere');
SET @generic_vulnerability_exposure_of_core_dump_file_to_an_unauthorized_control_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of Core Dump File to an Unauthorized Control Sphere');
SET @generic_vulnerability_exposure_of_access_control_list_files_to_an_unauthorized_control_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of Access Control List Files to an Unauthorized Control Sphere');
SET @generic_vulnerability_exposure_of_backup_file_to_an_unauthorized_control_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of Backup File to an Unauthorized Control Sphere');
SET @generic_vulnerability_information_leak_through_test_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Test Code');
SET @generic_vulnerability_information_leak_through_log_files_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Log Files');
SET @generic_vulnerability_information_leak_through_server_log_files_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Server Log Files');
SET @generic_vulnerability_information_leak_through_debug_log_files_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Debug Log Files');
SET @generic_vulnerability_information_leak_through_shell_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Shell Error Message');
SET @generic_vulnerability_information_leak_through_servlet_runtime_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Servlet Runtime Error Message');
SET @generic_vulnerability_information_leak_through_java_runtime_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Java Runtime Error Message');
SET @generic_vulnerability_file_and_directory_information_exposure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'File and Directory Information Exposure');
SET @generic_vulnerability_information_leak_through_persistent_cookies_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Persistent Cookies');
SET @generic_vulnerability_information_leak_through_source_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Source Code');
SET @generic_vulnerability_information_leak_through_include_source_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Include Source Code');
SET @generic_vulnerability_information_leak_through_cleanup_log_files_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Cleanup Log Files');
SET @generic_vulnerability_use_of_singleton_pattern_in_a_non_thread_safe_manner_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Singleton Pattern in a Non-thread-safe Manner');
SET @generic_vulnerability_failure_to_use_a_standardized_error_handling_mechanism_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Use a Standardized Error Handling Mechanism');
SET @generic_vulnerability_use_of_dynamic_class_loading_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Dynamic Class Loading');
SET @generic_vulnerability_suspicious_comment_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Suspicious Comment');
SET @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Hard-coded, Security-relevant Constants');
SET @generic_vulnerability_information_leak_through_directory_listing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Directory Listing');
SET @generic_vulnerability_missing_password_field_masking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Password Field Masking');
SET @generic_vulnerability_information_leak_through_server_error_message_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Server Error Message');
SET @generic_vulnerability_incorrect_behavior_order_authorization_before_parsing_and_canonicalization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization');
SET @generic_vulnerability_files_or_directories_accessible_to_external_parties_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Files or Directories Accessible to External Parties');
SET @generic_vulnerability_command_shell_in_externally_accessible_directory_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Command Shell in Externally Accessible Directory');
SET @generic_vulnerability_asp_net_misconfiguration_not_using_input_validation_framework_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Not Using Input Validation Framework');
SET @generic_vulnerability_j2ee_misconfiguration_plaintext_password_in_configuration_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Misconfiguration: Plaintext Password in Configuration File');
SET @generic_vulnerability_asp_net_misconfiguration_use_of_identity_impersonation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'ASP.NET Misconfiguration: Use of Identity Impersonation');
SET @generic_vulnerability_concurrency_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Concurrency Issues');
SET @generic_vulnerability_use_of_getlogin_in_multithreaded_application_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of getlogin() in Multithreaded Application');
SET @generic_vulnerability_often_misused_arguments_and_parameters_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Often Misused: Arguments and Parameters');
SET @generic_vulnerability_use_of_umask_with_chmod_style_argument_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of umask() with chmod-style Argument');
SET @generic_vulnerability_dead_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Dead Code');
SET @generic_vulnerability_return_of_stack_variable_address_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Return of Stack Variable Address');
SET @generic_vulnerability_unused_variable_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unused Variable');
SET @generic_vulnerability_sql_injection_hibernate_id := (SELECT id FROM GenericVulnerability WHERE Name = 'SQL Injection: Hibernate');
SET @generic_vulnerability_reliance_on_cookies_without_validation_and_integrity_checking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Cookies without Validation and Integrity Checking');
SET @generic_vulnerability_access_control_bypass_through_user_controlled_sql_primary_key_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access Control Bypass Through User-Controlled SQL Primary Key');
SET @generic_vulnerability_unsynchronized_access_to_shared_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unsynchronized Access to Shared Data');
SET @generic_vulnerability_finalize_method_without_super_finalize_id := (SELECT id FROM GenericVulnerability WHERE Name = 'finalize() Method Without super.finalize()');
SET @generic_vulnerability_expression_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Expression Issues');
SET @generic_vulnerability_expression_is_always_false_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Expression is Always False');
SET @generic_vulnerability_expression_is_always_true_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Expression is Always True');
SET @generic_vulnerability_call_to_thread_run_instead_of_start_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Call to Thread run() instead of start()');
SET @generic_vulnerability_failure_to_follow_specification_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Follow Specification');
SET @generic_vulnerability_ejb_bad_practices_use_of_synchronization_primitives_id := (SELECT id FROM GenericVulnerability WHERE Name = 'EJB Bad Practices: Use of Synchronization Primitives');
SET @generic_vulnerability_ejb_bad_practices_use_of_awt_swing_id := (SELECT id FROM GenericVulnerability WHERE Name = 'EJB Bad Practices: Use of AWT Swing');
SET @generic_vulnerability_ejb_bad_practices_use_of_java_i_o_id := (SELECT id FROM GenericVulnerability WHERE Name = 'EJB Bad Practices: Use of Java I/O');
SET @generic_vulnerability_ejb_bad_practices_use_of_sockets_id := (SELECT id FROM GenericVulnerability WHERE Name = 'EJB Bad Practices: Use of Sockets');
SET @generic_vulnerability_ejb_bad_practices_use_of_class_loader_id := (SELECT id FROM GenericVulnerability WHERE Name = 'EJB Bad Practices: Use of Class Loader');
SET @generic_vulnerability_j2ee_bad_practices_non_serializable_object_stored_in_session_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Bad Practices: Non-serializable Object Stored in Session');
SET @generic_vulnerability_clone_method_without_super_clone_id := (SELECT id FROM GenericVulnerability WHERE Name = 'clone() Method Without super.clone()');
SET @generic_vulnerability_object_model_violation_just_one_of_equals_and_hashcode_defined_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Object Model Violation: Just One of Equals and Hashcode Defined');
SET @generic_vulnerability_array_declared_public_final_and_static_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Array Declared Public, Final, and Static');
SET @generic_vulnerability_finalize_method_declared_public_id := (SELECT id FROM GenericVulnerability WHERE Name = 'finalize() Method Declared Public');
SET @generic_vulnerability_return_inside_finally_block_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Return Inside Finally Block');
SET @generic_vulnerability_empty_synchronized_block_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Empty Synchronized Block');
SET @generic_vulnerability_explicit_call_to_finalize_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Explicit Call to Finalize()');
SET @generic_vulnerability_assignment_of_a_fixed_address_to_a_pointer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Assignment of a Fixed Address to a Pointer');
SET @generic_vulnerability_attempt_to_access_child_of_a_non_structure_pointer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Attempt to Access Child of a Non-structure Pointer');
SET @generic_vulnerability_call_to_non_ubiquitous_api_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Call to Non-ubiquitous API');
SET @generic_vulnerability_free_of_memory_not_on_the_heap_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Free of Memory not on the Heap');
SET @generic_vulnerability_sensitive_data_storage_in_improperly_locked_memory_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Sensitive Data Storage in Improperly Locked Memory');
SET @generic_vulnerability_authentication_bypass_issues_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass Issues');
SET @generic_vulnerability_authentication_bypass_openssl_ctx_object_modified_after_ssl_objects_are_created_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created');
SET @generic_vulnerability_j2ee_framework_saving_unserializable_objects_to_disk_id := (SELECT id FROM GenericVulnerability WHERE Name = 'J2EE Framework: Saving Unserializable Objects to Disk');
SET @generic_vulnerability_comparison_of_object_references_instead_of_object_contents_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Comparison of Object References Instead of Object Contents');
SET @generic_vulnerability_incorrect_semantic_object_comparison_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Semantic Object Comparison');
SET @generic_vulnerability_use_of_wrong_operator_in_string_comparison_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Wrong Operator in String Comparison');
SET @generic_vulnerability_information_leak_through_query_strings_in_get_request_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Query Strings in GET Request');
SET @generic_vulnerability_trust_of_openssl_certificate_without_validation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trust of OpenSSL Certificate Without Validation');
SET @generic_vulnerability_failure_to_catch_all_exceptions_in_servlet_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Catch All Exceptions in Servlet ');
SET @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id := (SELECT id FROM GenericVulnerability WHERE Name = 'URL Redirection to Untrusted Site (''Open Redirect'')');
SET @generic_vulnerability_client_side_enforcement_of_server_side_security_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Client-Side Enforcement of Server-Side Security');
SET @generic_vulnerability_use_of_client_side_authentication_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Client-Side Authentication');
SET @generic_vulnerability_deprecated_entries_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Deprecated Entries');
SET @generic_vulnerability_multiple_binds_to_the_same_port_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Multiple Binds to the Same Port');
SET @generic_vulnerability_unchecked_input_for_loop_condition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unchecked Input for Loop Condition');
SET @generic_vulnerability_public_static_final_field_references_mutable_object_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Public Static Final Field References Mutable Object');
SET @generic_vulnerability_struts_non_private_field_in_actionform_class_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Struts: Non-private Field in ActionForm Class');
SET @generic_vulnerability_double_checked_locking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Double-Checked Locking');
SET @generic_vulnerability_externally_controlled_reference_to_a_resource_in_another_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Externally Controlled Reference to a Resource in Another Sphere');
SET @generic_vulnerability_information_leak_through_xml_external_entity_file_disclosure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through XML External Entity File Disclosure');
SET @generic_vulnerability_information_leak_through_indexing_of_private_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Indexing of Private Data');
SET @generic_vulnerability_insufficient_session_expiration_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Session Expiration');
SET @generic_vulnerability_sensitive_cookie_in_https_session_without_secure_attribute_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Sensitive Cookie in HTTPS Session Without ''Secure'' Attribute');
SET @generic_vulnerability_information_leak_through_comments_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak Through Comments');
SET @generic_vulnerability_incomplete_identification_of_uploaded_file_variables_php_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Identification of Uploaded File Variables (PHP)');
SET @generic_vulnerability_reachable_assertion_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reachable Assertion');
SET @generic_vulnerability_exposed_unsafe_activex_method_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposed Unsafe ActiveX Method');
SET @generic_vulnerability_dangling_database_cursor_cursor_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Dangling Database Cursor (''Cursor Injection'')');
SET @generic_vulnerability_unverified_password_change_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unverified Password Change');
SET @generic_vulnerability_variable_extraction_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Variable Extraction Error');
SET @generic_vulnerability_unvalidated_function_hook_arguments_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unvalidated Function Hook Arguments');
SET @generic_vulnerability_unsafe_activex_control_marked_safe_for_scripting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unsafe ActiveX Control Marked Safe For Scripting');
SET @generic_vulnerability_executable_regular_expression_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Executable Regular Expression Error');
SET @generic_vulnerability_permissive_regular_expression_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Permissive Regular Expression');
SET @generic_vulnerability_null_byte_interaction_error_poison_null_byte_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Null Byte Interaction Error (Poison Null Byte)');
SET @generic_vulnerability_dynamic_variable_evaluation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Dynamic Variable Evaluation');
SET @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call with Incorrectly Specified Arguments');
SET @generic_vulnerability_weaknesses_in_owasp_top_ten_2007_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in OWASP Top Ten (2007)');
SET @generic_vulnerability_weaknesses_examined_by_samate_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses Examined by SAMATE');
SET @generic_vulnerability_resource_specific_weaknesses_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Resource-specific Weaknesses');
SET @generic_vulnerability_weaknesses_that_affect_files_or_directories_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses that Affect Files or Directories');
SET @generic_vulnerability_weaknesses_that_affect_memory_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses that Affect Memory');
SET @generic_vulnerability_weaknesses_that_affect_system_processes_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses that Affect System Processes');
SET @generic_vulnerability_weaknesses_used_by_nvd_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses Used by NVD');
SET @generic_vulnerability_not_failing_securely_failing_open_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Not Failing Securely (''Failing Open'')');
SET @generic_vulnerability_failure_to_use_economy_of_mechanism_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Use Economy of Mechanism');
SET @generic_vulnerability_failure_to_use_complete_mediation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Use Complete Mediation');
SET @generic_vulnerability_access_control_bypass_through_user_controlled_key_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access Control Bypass Through User-Controlled Key');
SET @generic_vulnerability_weak_password_recovery_mechanism_for_forgotten_password_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weak Password Recovery Mechanism for Forgotten Password');
SET @generic_vulnerability_insufficient_filtering_of_file_and_other_resource_names_for_executable_content_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Filtering of File and Other Resource Names for Executable Content');
SET @generic_vulnerability_external_control_of_critical_state_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Control of Critical State Data');
SET @generic_vulnerability_failure_to_sanitize_data_within_xpath_expressions_xpath_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data within XPath Expressions (''XPath injection'')');
SET @generic_vulnerability_improper_sanitization_of_http_headers_for_scripting_syntax_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Sanitization of HTTP Headers for Scripting Syntax');
SET @generic_vulnerability_overly_restrictive_account_lockout_mechanism_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Overly Restrictive Account Lockout Mechanism');
SET @generic_vulnerability_reliance_on_file_name_or_extension_of_externally_supplied_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on File Name or Extension of Externally-Supplied File');
SET @generic_vulnerability_use_of_non_canonical_url_paths_for_authorization_decisions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Non-Canonical URL Paths for Authorization Decisions');
SET @generic_vulnerability_incorrect_use_of_privileged_apis_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Use of Privileged APIs');
SET @generic_vulnerability_reliance_on_obfuscation_or_encryption_of_security_relevant_inputs_without_integrity_checking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking');
SET @generic_vulnerability_trusting_http_permission_methods_on_the_server_side_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Trusting HTTP Permission Methods on the Server Side');
SET @generic_vulnerability_information_leak_through_wsdl_file_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Information Leak through WSDL File');
SET @generic_vulnerability_failure_to_sanitize_data_within_xquery_expressions_xquery_injection_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Sanitize Data within XQuery Expressions (''XQuery Injection'')');
SET @generic_vulnerability_insufficient_compartmentalization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Compartmentalization');
SET @generic_vulnerability_reliance_on_a_single_factor_in_a_security_decision_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on a Single Factor in a Security Decision');
SET @generic_vulnerability_insufficient_psychological_acceptability_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Psychological Acceptability');
SET @generic_vulnerability_reliance_on_security_through_obscurity_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Security through Obscurity');
SET @generic_vulnerability_violation_of_secure_design_principles_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Violation of Secure Design Principles');
SET @generic_vulnerability_weaknesses_in_software_written_in_c_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in Software Written in C');
SET @generic_vulnerability_weaknesses_in_software_written_in_c_659_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in Software Written in C++');
SET @generic_vulnerability_weaknesses_in_software_written_in_java_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in Software Written in Java');
SET @generic_vulnerability_weaknesses_in_software_written_in_php_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in Software Written in PHP');
SET @generic_vulnerability_insufficient_synchronization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Synchronization');
SET @generic_vulnerability_use_of_a_non_reentrant_function_in_an_unsynchronized_context_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of a Non-reentrant Function in an Unsynchronized Context');
SET @generic_vulnerability_improper_control_of_a_resource_through_its_lifetime_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Control of a Resource Through its Lifetime');
SET @generic_vulnerability_improper_initialization_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Initialization');
SET @generic_vulnerability_operation_on_resource_in_wrong_phase_of_lifetime_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Operation on Resource in Wrong Phase of Lifetime');
SET @generic_vulnerability_insufficient_locking_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Locking');
SET @generic_vulnerability_exposure_of_resource_to_wrong_sphere_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposure of Resource to Wrong Sphere');
SET @generic_vulnerability_incorrect_resource_transfer_between_spheres_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Resource Transfer Between Spheres');
SET @generic_vulnerability_always_incorrect_control_flow_implementation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Always-Incorrect Control Flow Implementation');
SET @generic_vulnerability_lack_of_administrator_control_over_security_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Lack of Administrator Control over Security');
SET @generic_vulnerability_operation_on_a_resource_after_expiration_or_release_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Operation on a Resource after Expiration or Release');
SET @generic_vulnerability_external_influence_of_sphere_definition_id := (SELECT id FROM GenericVulnerability WHERE Name = 'External Influence of Sphere Definition');
SET @generic_vulnerability_uncontrolled_recursion_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncontrolled Recursion');
SET @generic_vulnerability_duplicate_operations_on_resource_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Duplicate Operations on Resource');
SET @generic_vulnerability_use_of_potentially_dangerous_function_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Potentially Dangerous Function');
SET @generic_vulnerability_weakness_base_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weakness Base Elements');
SET @generic_vulnerability_composites_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Composites');
SET @generic_vulnerability_chain_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Chain Elements');
SET @generic_vulnerability_integer_overflow_to_buffer_overflow_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Integer Overflow to Buffer Overflow');
SET @generic_vulnerability_incorrect_conversion_between_numeric_types_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Conversion between Numeric Types');
SET @generic_vulnerability_incorrect_calculation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Calculation');
SET @generic_vulnerability_function_call_with_incorrect_order_of_arguments_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call With Incorrect Order of Arguments');
SET @generic_vulnerability_failure_to_provide_specified_functionality_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Provide Specified Functionality');
SET @generic_vulnerability_function_call_with_incorrect_number_of_arguments_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call With Incorrect Number of Arguments');
SET @generic_vulnerability_function_call_with_incorrect_argument_type_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call With Incorrect Argument Type');
SET @generic_vulnerability_function_call_with_incorrectly_specified_argument_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call With Incorrectly Specified Argument Value');
SET @generic_vulnerability_function_call_with_incorrect_variable_or_reference_as_argument_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Function Call With Incorrect Variable or Reference as Argument');
SET @generic_vulnerability_permission_race_condition_during_resource_copy_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Permission Race Condition During Resource Copy');
SET @generic_vulnerability_unchecked_return_value_to_null_pointer_dereference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unchecked Return Value to NULL Pointer Dereference');
SET @generic_vulnerability_insufficient_control_flow_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Control Flow Management');
SET @generic_vulnerability_incomplete_blacklist_to_cross_site_scripting_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Blacklist to Cross-Site Scripting');
SET @generic_vulnerability_protection_mechanism_failure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Protection Mechanism Failure');
SET @generic_vulnerability_use_of_multiple_resources_with_duplicate_identifier_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Multiple Resources with Duplicate Identifier');
SET @generic_vulnerability_use_of_low_level_functionality_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Low-Level Functionality');
SET @generic_vulnerability_incorrect_behavior_order_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Behavior Order');
SET @generic_vulnerability_insufficient_comparison_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Comparison');
SET @generic_vulnerability_redirect_without_exit_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Redirect Without Exit');
SET @generic_vulnerability_development_concepts_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Development Concepts');
SET @generic_vulnerability_seven_pernicious_kingdoms_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Seven Pernicious Kingdoms');
SET @generic_vulnerability_weaknesses_introduced_during_design_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses Introduced During Design');
SET @generic_vulnerability_weaknesses_introduced_during_implementation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses Introduced During Implementation');
SET @generic_vulnerability_failure_to_handle_exceptional_conditions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Failure to Handle Exceptional Conditions');
SET @generic_vulnerability_incorrect_type_conversion_or_cast_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Type Conversion or Cast');
SET @generic_vulnerability_incorrect_control_flow_scoping_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Control Flow Scoping');
SET @generic_vulnerability_use_of_incorrectly_resolved_name_or_reference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Incorrectly-Resolved Name or Reference');
SET @generic_vulnerability_improper_enforcement_of_message_or_data_structure_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Enforcement of Message or Data Structure');
SET @generic_vulnerability_incorrect_ownership_assignment_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Ownership Assignment');
SET @generic_vulnerability_named_chains_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Named Chains');
SET @generic_vulnerability_coding_standards_violation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Coding Standards Violation');
SET @generic_vulnerability_weaknesses_in_owasp_top_ten_2004_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in OWASP Top Ten (2004)');
SET @generic_vulnerability_owasp_top_ten_2007_category_a1_cross_site_scripting_xss_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A1 - Cross Site Scripting (XSS)');
SET @generic_vulnerability_owasp_top_ten_2007_category_a2_injection_flaws_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A2 - Injection Flaws');
SET @generic_vulnerability_owasp_top_ten_2007_category_a3_malicious_file_execution_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A3 - Malicious File Execution');
SET @generic_vulnerability_owasp_top_ten_2007_category_a4_insecure_direct_object_reference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference');
SET @generic_vulnerability_owasp_top_ten_2007_category_a5_cross_site_request_forgery_csrf_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery (CSRF)');
SET @generic_vulnerability_owasp_top_ten_2007_category_a6_information_leakage_and_improper_error_handling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling');
SET @generic_vulnerability_owasp_top_ten_2007_category_a7_broken_authentication_and_session_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management');
SET @generic_vulnerability_owasp_top_ten_2007_category_a8_insecure_cryptographic_storage_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A8 - Insecure Cryptographic Storage');
SET @generic_vulnerability_owasp_top_ten_2007_category_a9_insecure_communications_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A9 - Insecure Communications');
SET @generic_vulnerability_owasp_top_ten_2007_category_a10_failure_to_restrict_url_access_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2007 Category A10 - Failure to Restrict URL Access');
SET @generic_vulnerability_owasp_top_ten_2004_category_a1_unvalidated_input_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A1 - Unvalidated Input');
SET @generic_vulnerability_owasp_top_ten_2004_category_a2_broken_access_control_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A2 - Broken Access Control');
SET @generic_vulnerability_owasp_top_ten_2004_category_a3_broken_authentication_and_session_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management');
SET @generic_vulnerability_owasp_top_ten_2004_category_a4_cross_site_scripting_xss_flaws_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A4 - Cross-Site Scripting (XSS) Flaws');
SET @generic_vulnerability_owasp_top_ten_2004_category_a5_buffer_overflows_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A5 - Buffer Overflows');
SET @generic_vulnerability_owasp_top_ten_2004_category_a6_injection_flaws_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A6 - Injection Flaws');
SET @generic_vulnerability_owasp_top_ten_2004_category_a7_improper_error_handling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A7 - Improper Error Handling');
SET @generic_vulnerability_owasp_top_ten_2004_category_a8_insecure_storage_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A8 - Insecure Storage');
SET @generic_vulnerability_owasp_top_ten_2004_category_a9_denial_of_service_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A9 - Denial of Service');
SET @generic_vulnerability_owasp_top_ten_2004_category_a10_insecure_configuration_management_id := (SELECT id FROM GenericVulnerability WHERE Name = 'OWASP Top Ten 2004 Category A10 - Insecure Configuration Management');
SET @generic_vulnerability_incorrect_permission_assignment_for_critical_resource_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Permission Assignment for Critical Resource');
SET @generic_vulnerability_compiler_optimization_removal_or_modification_of_security_critical_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Compiler Optimization Removal or Modification of Security-critical Code');
SET @generic_vulnerability_weaknesses_addressed_by_the_cert_c_secure_coding_standard_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses Addressed by the CERT C Secure Coding Standard');
SET @generic_vulnerability_cert_c_secure_coding_section_01_preprocessor_pre_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 01 - Preprocessor (PRE)');
SET @generic_vulnerability_cert_c_secure_coding_section_02_declarations_and_initialization_dcl_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 02 - Declarations and Initialization (DCL)');
SET @generic_vulnerability_cert_c_secure_coding_section_03_expressions_exp_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 03 - Expressions (EXP)');
SET @generic_vulnerability_cert_c_secure_coding_section_04_integers_int_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 04 - Integers (INT)');
SET @generic_vulnerability_cert_c_secure_coding_section_05_floating_point_flp_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 05 - Floating Point (FLP)');
SET @generic_vulnerability_cert_c_secure_coding_section_06_arrays_arr_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 06 - Arrays (ARR)');
SET @generic_vulnerability_cert_c_secure_coding_section_07_characters_and_strings_str_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 07 - Characters and Strings (STR)');
SET @generic_vulnerability_cert_c_secure_coding_section_08_memory_management_mem_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 08 - Memory Management (MEM)');
SET @generic_vulnerability_cert_c_secure_coding_section_09_input_output_fio_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 09 - Input Output (FIO)');
SET @generic_vulnerability_cert_c_secure_coding_section_10_environment_env_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 10 - Environment (ENV)');
SET @generic_vulnerability_cert_c_secure_coding_section_11_signals_sig_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 11 - Signals (SIG)');
SET @generic_vulnerability_cert_c_secure_coding_section_12_error_handling_err_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 12 - Error Handling (ERR)');
SET @generic_vulnerability_cert_c_secure_coding_section_49_miscellaneous_msc_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 49 - Miscellaneous (MSC)');
SET @generic_vulnerability_cert_c_secure_coding_section_50_posix_pos_id := (SELECT id FROM GenericVulnerability WHERE Name = 'CERT C Secure Coding Section 50 - POSIX (POS)');
SET @generic_vulnerability_exposed_dangerous_method_or_function_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposed Dangerous Method or Function');
SET @generic_vulnerability_weaknesses_in_the_2009_cwe_sans_top_25_most_dangerous_programming_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in the 2009 CWE/SANS Top 25 Most Dangerous Programming Errors');
SET @generic_vulnerability_2009_top_25_insecure_interaction_between_components_id := (SELECT id FROM GenericVulnerability WHERE Name = '2009 Top 25 - Insecure Interaction Between Components');
SET @generic_vulnerability_2009_top_25_risky_resource_management_id := (SELECT id FROM GenericVulnerability WHERE Name = '2009 Top 25 - Risky Resource Management');
SET @generic_vulnerability_2009_top_25_porous_defenses_id := (SELECT id FROM GenericVulnerability WHERE Name = '2009 Top 25 - Porous Defenses');
SET @generic_vulnerability_improper_check_for_unusual_or_exceptional_conditions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Check for Unusual or Exceptional Conditions');
SET @generic_vulnerability_improper_handling_of_exceptional_conditions_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Handling of Exceptional Conditions');
SET @generic_vulnerability_missing_custom_error_page_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Custom Error Page');
SET @generic_vulnerability_selection_of_less_secure_algorithm_during_negotiation_algorithm_downgrade_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Selection of Less-Secure Algorithm During Negotiation (''Algorithm Downgrade'')');
SET @generic_vulnerability_reliance_on_undefined_unspecified_or_implementation_defined_behavior_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior');
SET @generic_vulnerability_use_of_a_one_way_hash_without_a_salt_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of a One-Way Hash without a Salt');
SET @generic_vulnerability_use_of_a_one_way_hash_with_a_predictable_salt_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of a One-Way Hash with a Predictable Salt');
SET @generic_vulnerability_free_of_pointer_not_at_start_of_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Free of Pointer not at Start of Buffer');
SET @generic_vulnerability_mismatched_memory_management_routines_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Mismatched Memory Management Routines');
SET @generic_vulnerability_release_of_invalid_pointer_or_reference_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Release of Invalid Pointer or Reference');
SET @generic_vulnerability_multiple_locks_of_a_critical_resource_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Multiple Locks of a Critical Resource');
SET @generic_vulnerability_multiple_unlocks_of_a_critical_resource_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Multiple Unlocks of a Critical Resource');
SET @generic_vulnerability_critical_variable_declared_public_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Critical Variable Declared Public');
SET @generic_vulnerability_access_to_critical_private_variable_via_public_method_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access to Critical Private Variable via Public Method');
SET @generic_vulnerability_incorrect_short_circuit_evaluation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incorrect Short Circuit Evaluation');
SET @generic_vulnerability_file_descriptor_exhaustion_id := (SELECT id FROM GenericVulnerability WHERE Name = 'File Descriptor Exhaustion');
SET @generic_vulnerability_allocation_of_resources_without_limits_or_throttling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Allocation of Resources Without Limits or Throttling');
SET @generic_vulnerability_missing_reference_to_active_allocated_resource_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Reference to Active Allocated Resource');
SET @generic_vulnerability_missing_release_of_resource_after_effective_lifetime_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Release of Resource after Effective Lifetime');
SET @generic_vulnerability_missing_reference_to_active_file_descriptor_or_handle_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Reference to Active File Descriptor or Handle');
SET @generic_vulnerability_allocation_of_file_descriptors_or_handles_without_limits_or_throttling_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Allocation of File Descriptors or Handles Without Limits or Throttling');
SET @generic_vulnerability_missing_release_of_file_descriptor_or_handle_after_effective_lifetime_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Missing Release of File Descriptor or Handle after Effective Lifetime');
SET @generic_vulnerability_unrestricted_recursive_entity_references_in_dtds_xml_bomb_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Unrestricted Recursive Entity References in DTDs (''XML Bomb'')');
SET @generic_vulnerability_regular_expression_without_anchors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Regular Expression without Anchors');
SET @generic_vulnerability_insufficient_logging_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Insufficient Logging');
SET @generic_vulnerability_logging_of_excessive_data_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Logging of Excessive Data');
SET @generic_vulnerability_use_of_rsa_algorithm_without_oaep_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of RSA Algorithm without OAEP');
SET @generic_vulnerability_improper_address_validation_in_ioctl_with_method_neither_i_o_control_code_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code');
SET @generic_vulnerability_exposed_ioctl_with_insufficient_access_control_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Exposed IOCTL with Insufficient Access Control');
SET @generic_vulnerability_operator_precedence_logic_error_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Operator Precedence Logic Error');
SET @generic_vulnerability_reliance_on_cookies_without_validation_and_integrity_checking_in_a_security_decision_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Cookies without Validation and Integrity Checking in a Security Decision');
SET @generic_vulnerability_use_of_path_manipulation_function_without_maximum_sized_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Path Manipulation Function without Maximum-sized Buffer');
SET @generic_vulnerability_access_of_memory_location_before_start_of_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access of Memory Location Before Start of Buffer');
SET @generic_vulnerability_out_of_bounds_write_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Out-of-bounds Write');
SET @generic_vulnerability_access_of_memory_location_after_end_of_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Access of Memory Location After End of Buffer');
SET @generic_vulnerability_uncontrolled_memory_allocation_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Uncontrolled Memory Allocation');
SET @generic_vulnerability_improper_filtering_of_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Filtering of Special Elements');
SET @generic_vulnerability_incomplete_filtering_of_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Filtering of Special Elements');
SET @generic_vulnerability_incomplete_filtering_of_one_or_more_instances_of_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Filtering of One or More Instances of Special Elements');
SET @generic_vulnerability_only_filtering_one_instance_of_a_special_element_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Only Filtering One Instance of a Special Element');
SET @generic_vulnerability_incomplete_filtering_of_multiple_instances_of_special_elements_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Incomplete Filtering of Multiple Instances of Special Elements');
SET @generic_vulnerability_only_filtering_special_elements_at_a_specified_location_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Only Filtering Special Elements at a Specified Location');
SET @generic_vulnerability_only_filtering_special_elements_relative_to_a_marker_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Only Filtering Special Elements Relative to a Marker');
SET @generic_vulnerability_only_filtering_special_elements_at_an_absolute_position_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Only Filtering Special Elements at an Absolute Position');
SET @generic_vulnerability_use_of_hard_coded_credentials_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Use of Hard-coded Credentials');
SET @generic_vulnerability_improper_control_of_interaction_frequency_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Improper Control of Interaction Frequency');
SET @generic_vulnerability_weaknesses_in_the_2010_cwe_sans_top_25_most_dangerous_programming_errors_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Weaknesses in the 2010 CWE/SANS Top 25 Most Dangerous Programming Errors');
SET @generic_vulnerability_2010_top_25_insecure_interaction_between_components_id := (SELECT id FROM GenericVulnerability WHERE Name = '2010 Top 25 - Insecure Interaction Between Components');
SET @generic_vulnerability_2010_top_25_risky_resource_management_id := (SELECT id FROM GenericVulnerability WHERE Name = '2010 Top 25 - Risky Resource Management');
SET @generic_vulnerability_2010_top_25_porous_defenses_id := (SELECT id FROM GenericVulnerability WHERE Name = '2010 Top 25 - Porous Defenses');
SET @generic_vulnerability_guessable_captcha_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Guessable CAPTCHA');
SET @generic_vulnerability_buffer_access_with_incorrect_length_value_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Access with Incorrect Length Value');
SET @generic_vulnerability_buffer_access_using_size_of_source_buffer_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Buffer Access Using Size of Source Buffer');
SET @generic_vulnerability_reliance_on_untrusted_inputs_in_a_security_decision_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Reliance on Untrusted Inputs in a Security Decision');
SET @generic_vulnerability_2010_top_25_weaknesses_on_the_cusp_id := (SELECT id FROM GenericVulnerability WHERE Name = '2010 Top 25 - Weaknesses On the Cusp');
SET @generic_vulnerability_research_concepts_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Research Concepts');
SET @generic_vulnerability_comprehensive_cwe_dictionary_id := (SELECT id FROM GenericVulnerability WHERE Name = 'Comprehensive CWE Dictionary');

-- ------------------------------------
-- INSERT CHANNEL SEVERITIES ---------
-- ------------------------------------
-- Fortify


-- Cat.NET
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'ACESEC01', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Process Command Execution', 'ACESEC02', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('File Canonicalization', 'ACESEC03', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Exception Information', 'ACESEC04', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Scripting', 'ACESEC05', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Redirection to User Controlled Site', 'ACESEC06', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XPath Injection', 'ACESEC07', @cat_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LDAP Injection', 'ACESEC08', @cat_net_channel_id);

-- CheckMarx
-- Apex Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Best Coding Practices: Hardcoded Id', 'Apex_Best_Coding_Practices_Hardcoded_Id', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Best Coding Practices: SOSL SOQL DML In Loop', 'Apex_Best_Coding_Practices_SOSL_SOQL_DML_In_Loop', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Best Coding Practices: Test Methods With No Assert', 'Apex_Best_Coding_Practices_Test_Methods_With_No_Assert', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex High Risk: Reflected XSS', 'Apex_High_Risk_Reflected_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex High Risk: Resource Injection', 'Apex_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex High Risk: SOQL SOSL Injection', 'Apex_High_Risk_SOQL_SOSL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex High Risk: Stored XSS', 'Apex_High_Risk_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Escape False Warning', 'Apex_Low_Visibility_Escape_False_Warning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Hardcoded Password', 'Apex_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Parameter Tampering', 'Apex_Low_Visibility_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Password misuse', 'Apex_Low_Visibility_Password_misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Potential Frame Injection', 'Apex_Low_Visibility_Potential_Frame_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Low Visibility: Second Order SOQL SOSL Injection', 'Apex_Low_Visibility_Second_Order_SOQL_SOSL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: Access Control', 'Apex_Medium_Threat_Access_Control', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: Cookies Scoping', 'Apex_Medium_Threat_Cookies_Scoping', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: Frame Spoofing', 'Apex_Medium_Threat_Frame_Spoofing', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: HttpSplitting', 'Apex_Medium_Threat_HttpSplitting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: URL Redirection Attack', 'Apex_Medium_Threat_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: Verbose Error Reporting', 'Apex_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apex Medium Threat: XSRF', 'Apex_Medium_Threat_XSRF', @checkmarx_channel_id);
-- ASP Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Aptca Methods Call Non Aptca Methods', 'ASP_Best_Coding_Practice_Aptca_Methods_Call_Non_Aptca_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Catch NullPointerException', 'ASP_Best_Coding_Practice_Catch_NullPointerException', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Catch Without General Exception Handling', 'ASP_Best_Coding_Practice_Catch_Without_General_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Dynamic SQL Queries', 'ASP_Best_Coding_Practice_Dynamic_SQL_Queries', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Empty Catch', 'ASP_Best_Coding_Practice_Empty_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: GetLastWin32Error Is Not Called After Pinvoke', 'ASP_Best_Coding_Practice_GetLastWin32Error_Is_Not_Called_After_Pinvoke', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Hardcoded Connection String', 'ASP_Best_Coding_Practice_Hardcoded_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Ignoring Method Return', 'ASP_Best_Coding_Practice_Ignoring_Method_Return', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Magic Numbers', 'ASP_Best_Coding_Practice_Magic_Numbers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Missing XML Validation', 'ASP_Best_Coding_Practice_Missing_XML_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Non Private Static Constructors', 'ASP_Best_Coding_Practice_Non_Private_Static_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: NULL Argument to Equals', 'ASP_Best_Coding_Practice_NULL_Argument_to_Equals', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Overly Broad Catch', 'ASP_Best_Coding_Practice_Overly_Broad_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Pages Without Global Error Handler', 'ASP_Best_Coding_Practice_Pages_Without_Global_Error_Handler', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: PersistSecurityInfo is True', 'ASP_Best_Coding_Practice_PersistSecurityInfo_is_True', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Sockets in WebApp', 'ASP_Best_Coding_Practice_Sockets_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Threads in WebApp', 'ASP_Best_Coding_Practice_Threads_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Unclosed Objects', 'ASP_Best_Coding_Practice_Unclosed_Objects', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Uninitialized Variables', 'ASP_Best_Coding_Practice_Uninitialized_Variables', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Unvalidated Arguments Of Public Methods', 'ASP_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Use of System Output Stream', 'ASP_Best_Coding_Practice_Use_of_System_Output_Stream', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Visible Fields', 'ASP_Best_Coding_Practice_Visible_Fields', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Best Coding Practice: Visible Pointers', 'ASP_Best_Coding_Practice_Visible_Pointers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic 2nd Order SQL Injection', 'ASP_Heuristic_Heuristic_2nd_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic DB Paramater Tampering', 'ASP_Heuristic_Heuristic_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic Parameter Tampering', 'ASP_Heuristic_Heuristic_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic SQL Injection', 'ASP_Heuristic_Heuristic_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic Stored XSS', 'ASP_Heuristic_Heuristic_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Heuristic: Heuristic XSRF', 'ASP_Heuristic_Heuristic_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Code Injection', 'ASP_High_Risk_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Command Injection', 'ASP_High_Risk_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Connection String Injection', 'ASP_High_Risk_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: LDAP Injection', 'ASP_High_Risk_LDAP_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Reflected XSS All Clients', 'ASP_High_Risk_Reflected_XSS_All_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Resource Injection', 'ASP_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Second Order SQL Injection', 'ASP_High_Risk_Second_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: SQL injection', 'ASP_High_Risk_SQL_injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: Stored XSS', 'ASP_High_Risk_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: UTF7 XSS', 'ASP_High_Risk_UTF7_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP High Risk: XPath Injection', 'ASP_High_Risk_XPath_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Blind SQL Injections', 'ASP_Low_Visibility_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Client Side Only Validation', 'ASP_Low_Visibility_Client_Side_Only_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Dangerous File Upload', 'ASP_Low_Visibility_Dangerous_File_Upload', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: DoS by Unreleased Resources', 'ASP_Low_Visibility_DoS_by_Unreleased_Resources', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Equals without GetHashCode', 'ASP_Low_Visibility_Equals_without_GetHashCode', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Files Canonicalization Problems', 'ASP_Low_Visibility_Files_Canonicalization_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Hardcoded Absolute Path', 'ASP_Low_Visibility_Hardcoded_Absolute_Path', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Hardcoded Password', 'ASP_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Hardcoded password in Connection String', 'ASP_Low_Visibility_Hardcoded_password_in_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Impersonation Issue', 'ASP_Low_Visibility_Impersonation_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Improper Exception Handling', 'ASP_Low_Visibility_Improper_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Improper Session Management', 'ASP_Low_Visibility_Improper_Session_Management', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Improper Transaction Handling', 'ASP_Low_Visibility_Improper_Transaction_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Insecure Randomness', 'ASP_Low_Visibility_Insecure_Randomness', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: JavaScript Hhijacking', 'ASP_Low_Visibility_JavaScript_Hhijacking', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Leaving Temporary Files', 'ASP_Low_Visibility_Leaving_Temporary_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Log Forgery', 'ASP_Low_Visibility_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Password Misuse', 'ASP_Low_Visibility_Password_Misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Personal Info In Cookie', 'ASP_Low_Visibility_Personal_Info_In_Cookie', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Script Poinsoning', 'ASP_Low_Visibility_Script_Poinsoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Server Code In Client Comment', 'ASP_Low_Visibility_Server_Code_In_Client_Comment', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Session Clearing Problems', 'ASP_Low_Visibility_Session_Clearing_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Session Poisoning', 'ASP_Low_Visibility_Session_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: Thread Safety Issue', 'ASP_Low_Visibility_Thread_Safety_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: URL Canonicalization Issue', 'ASP_Low_Visibility_URL_Canonicalization_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: URL Redirection Attack', 'ASP_Low_Visibility_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Low Visibility: XSS Evasion Attack', 'ASP_Low_Visibility_XSS_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Buffer Overflow', 'ASP_Medium_Threat_Buffer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: DB Paramater Tampering', 'ASP_Medium_Threat_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: DoS by Sleep', 'ASP_Medium_Threat_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Files Manipulation', 'ASP_Medium_Threat_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Hardcoded Cryptographic Keys', 'ASP_Medium_Threat_Hardcoded_Cryptographic_Keys', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: HttpSplitting', 'ASP_Medium_Threat_HttpSplitting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Integer Overflow', 'ASP_Medium_Threat_Integer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Mutex Problem', 'ASP_Medium_Threat_Mutex_Problem', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Parameter Tampering', 'ASP_Medium_Threat_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Privacy Violation', 'ASP_Medium_Threat_Privacy_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Reflected XSS Specific Clients', 'ASP_Medium_Threat_Reflected_XSS_Specific_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: SQL Injection Evasion Attack', 'ASP_Medium_Threat_SQL_Injection_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Stored Code Injection', 'ASP_Medium_Threat_Stored_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Trust Boundary Violation', 'ASP_Medium_Threat_Trust_Boundary_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Unclosed Connection', 'ASP_Medium_Threat_Unclosed_Connection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Untrusted Activex', 'ASP_Medium_Threat_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: Verbose Error Reporting', 'ASP_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP Medium Threat: XSRF', 'ASP_Medium_Threat_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: CookieLess', 'ASP_WebConfig_CookieLess', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: CustomError', 'ASP_WebConfig_CustomError', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: DebugEnabled', 'ASP_WebConfig_DebugEnabled', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: HardcodedCredentials', 'ASP_WebConfig_HardcodedCredentials', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: HttpOnlyCookies XSS', 'ASP_WebConfig_HttpOnlyCookies_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: NonUniqueFormName', 'ASP_WebConfig_NonUniqueFormName', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: RequireSSL', 'ASP_WebConfig_RequireSSL', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: SlidingExpiration', 'ASP_WebConfig_SlidingExpiration', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP WebConfig: TraceEnabled', 'ASP_WebConfig_TraceEnabled', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client DoS By Sleep', 'JavaScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Unstructured Error Handling', 'JavaScript_Vulnerabilities_Client_Unstructured_Error_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Untrusted Activex', 'JavaScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Cookies Inspection', 'JavaScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Code Injection', 'JavaScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Cookie Poisoning', 'JavaScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM URL Redirection Attack', 'JavaScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSRF', 'JavaScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSS', 'JavaScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Weak Password Authentication', 'JavaScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client DoS By Sleep', 'VbScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client Untrusted Activex', 'VbScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Cookies Inspection', 'VbScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Code Injection', 'VbScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Cookie Poisoning', 'VbScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM URL Redirection Attack', 'VbScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSRF', 'VbScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSS', 'VbScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Weak Password Authentication', 'VbScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);

-- CPP Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Empty Catch', 'CPP_Best_Coding_Practice_Empty_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Non Private Static Constructors', 'CPP_Best_Coding_Practice_Non_Private_Static_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Overly Broad Catch', 'CPP_Best_Coding_Practice_Overly_Broad_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Potential OffByOne in Loops', 'CPP_Best_Coding_Practice_Potential_OffByOne_in_Loops', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Single Line If Statement', 'CPP_Best_Coding_Practice_Single_Line_If_Statement', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Unvalidated Arguments Of Public Methods', 'CPP_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Best Coding Practice: Use Of Goto', 'CPP_Best_Coding_Practice_Use_Of_Goto', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow boundedcpy', 'CPP_Buffer_Overflow_Buffer_Overflow_boundedcpy', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow boundedcpy2', 'CPP_Buffer_Overflow_Buffer_Overflow_boundedcpy2', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow cin', 'CPP_Buffer_Overflow_Buffer_Overflow_cin', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow cpycat', 'CPP_Buffer_Overflow_Buffer_Overflow_cpycat', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow fgets', 'CPP_Buffer_Overflow_Buffer_Overflow_fgets', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow scanf', 'CPP_Buffer_Overflow_Buffer_Overflow_scanf', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Buffer Overflow unbounded', 'CPP_Buffer_Overflow_Buffer_Overflow_unbounded', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: Format String Attack', 'CPP_Buffer_Overflow_Format_String_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: MultiByte String Length', 'CPP_Buffer_Overflow_MultiByte_String_Length', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: OffByOne arrays', 'CPP_Buffer_Overflow_OffByOne_arrays', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: OffByOne Loops', 'CPP_Buffer_Overflow_OffByOne_Loops', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: OffByOne methods', 'CPP_Buffer_Overflow_OffByOne_methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Buffer Overflow: String Termination Error', 'CPP_Buffer_Overflow_String_Termination_Error', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Freed Pointer Not Set To Null', 'CPP_Heuristic_Freed_Pointer_Not_Set_To_Null', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic 2nd Order Buffer Overflow malloc', 'CPP_Heuristic_Heuristic_2nd_Order_Buffer_Overflow_malloc', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic 2nd Order Buffer Overflow read', 'CPP_Heuristic_Heuristic_2nd_Order_Buffer_Overflow_read', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic 2nd Order SQL Injection', 'CPP_Heuristic_Heuristic_2nd_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic Buffer Overflow malloc', 'CPP_Heuristic_Heuristic_Buffer_Overflow_malloc', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic Buffer Overflow read', 'CPP_Heuristic_Heuristic_Buffer_Overflow_read', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic CGI Stored XSS', 'CPP_Heuristic_Heuristic_CGI_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic DB Parameter Tampering', 'CPP_Heuristic_Heuristic_DB_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic NULL Pointer Dereference1', 'CPP_Heuristic_Heuristic_NULL_Pointer_Dereference1', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic NULL Pointer Dereference2', 'CPP_Heuristic_Heuristic_NULL_Pointer_Dereference2', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic Parameter Tampering', 'CPP_Heuristic_Heuristic_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Heuristic: Heuristic SQL Injection', 'CPP_Heuristic_Heuristic_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: CGI Reflected XSS', 'CPP_High_Risk_CGI_Reflected_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: CGI Stored XSS', 'CPP_High_Risk_CGI_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: Command Injection', 'CPP_High_Risk_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: Connection String Injection', 'CPP_High_Risk_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: Process Control', 'CPP_High_Risk_Process_Control', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: Resource Injection', 'CPP_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP High Risk: SQL injection', 'CPP_High_Risk_SQL_injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Boolean Overflow', 'CPP_Integer_Overflow_Boolean_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Char Overflow', 'CPP_Integer_Overflow_Char_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Float Overflow', 'CPP_Integer_Overflow_Float_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Integer Overflow', 'CPP_Integer_Overflow_Integer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Long Overflow', 'CPP_Integer_Overflow_Long_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Integer Overflow: Short Overflow', 'CPP_Integer_Overflow_Short_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Arithmenic Operation On Boolean', 'CPP_Low_Visibility_Arithmenic_Operation_On_Boolean', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Blind SQL Injections', 'CPP_Low_Visibility_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Deprecated And Obsolete', 'CPP_Low_Visibility_Deprecated_And_Obsolete', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: DoS by Unreleased Resources', 'CPP_Low_Visibility_DoS_by_Unreleased_Resources', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Hardcoded Absolute Path', 'CPP_Low_Visibility_Hardcoded_Absolute_Path', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Hardcoded Password', 'CPP_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Improper Exception Handling', 'CPP_Low_Visibility_Improper_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Improper Transaction Handling', 'CPP_Low_Visibility_Improper_Transaction_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Insecure Temporary File', 'CPP_Low_Visibility_Insecure_Temporary_File', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Leaving Temporary Files', 'CPP_Low_Visibility_Leaving_Temporary_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Leftover Debug Code', 'CPP_Low_Visibility_Leftover_Debug_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Log Forgery', 'CPP_Low_Visibility_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Password Misuse', 'CPP_Low_Visibility_Password_Misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Sizeof Pointer Argument', 'CPP_Low_Visibility_Sizeof_Pointer_Argument', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Stored Blind SQL Injections', 'CPP_Low_Visibility_Stored_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Low Visibility: Unchecked Array Index', 'CPP_Low_Visibility_Unchecked_Array_Index', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Dangerous Functions', 'CPP_Medium_Threat_Dangerous_Functions', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: DB Paramater Tampering', 'CPP_Medium_Threat_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: DoS by Sleep', 'CPP_Medium_Threat_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Double Free', 'CPP_Medium_Threat_Double_Free', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Environment Injection', 'CPP_Medium_Threat_Environment_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Files Manipulation', 'CPP_Medium_Threat_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Hardcoded Cryptographic Keys', 'CPP_Medium_Threat_Hardcoded_Cryptographic_Keys', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Hardcoded password in Connection String', 'CPP_Medium_Threat_Hardcoded_password_in_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Heap Inspection', 'CPP_Medium_Threat_Heap_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Improperly Locked Memory', 'CPP_Medium_Threat_Improperly_Locked_Memory', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Memory Leak', 'CPP_Medium_Threat_Memory_Leak', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Parameter Tampering', 'CPP_Medium_Threat_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Setting Manipulation', 'CPP_Medium_Threat_Setting_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Unchecked Return Value', 'CPP_Medium_Threat_Unchecked_Return_Value', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Use After Free', 'CPP_Medium_Threat_Use_After_Free', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Use of Uninitialized Variable', 'CPP_Medium_Threat_Use_of_Uninitialized_Variable', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Use of Zero Initialized Pointer', 'CPP_Medium_Threat_Use_of_Zero_Initialized_Pointer', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Verbose Error Reporting', 'CPP_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Medium Threat: Wrong Memory Allocation', 'CPP_Medium_Threat_Wrong_Memory_Allocation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Second Order SQL Injection', 'CPP_Stored_Vulnerabilities_Second_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Buffer Overflow boundcpy', 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_boundcpy', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Buffer Overflow cpycat', 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_cpycat', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Buffer Overflow fgets', 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_fgets', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Buffer Overflow fscanf', 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_fscanf', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Command Injection', 'CPP_Stored_Vulnerabilities_Stored_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Connection String Injection', 'CPP_Stored_Vulnerabilities_Stored_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored DB Paramater Tampering', 'CPP_Stored_Vulnerabilities_Stored_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored DoS by Sleep', 'CPP_Stored_Vulnerabilities_Stored_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Environment Injection', 'CPP_Stored_Vulnerabilities_Stored_Environment_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Files Manipulation', 'CPP_Stored_Vulnerabilities_Stored_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Format String Attack', 'CPP_Stored_Vulnerabilities_Stored_Format_String_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Log Forgery', 'CPP_Stored_Vulnerabilities_Stored_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Parameter Tampering', 'CPP_Stored_Vulnerabilities_Stored_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Process Control', 'CPP_Stored_Vulnerabilities_Stored_Process_Control', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CPP Stored Vulnerabilities: Stored Resource Injection', 'CPP_Stored_Vulnerabilities_Stored_Resource_Injection', @checkmarx_channel_id);


-- CSharp Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Aptca Methods Call Non Aptca Methods', 'CSharp_Best_Coding_Practice_Aptca_Methods_Call_Non_Aptca_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Catch NullPointerException', 'CSharp_Best_Coding_Practice_Catch_NullPointerException', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Catch Without General Exception Handling', 'CSharp_Best_Coding_Practice_Catch_Without_General_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Dynamic SQL Queries', 'CSharp_Best_Coding_Practice_Dynamic_SQL_Queries', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Empty Catch', 'CSharp_Best_Coding_Practice_Empty_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: GetLastWin32Error Is Not Called After Pinvoke', 'CSharp_Best_Coding_Practice_GetLastWin32Error_Is_Not_Called_After_Pinvoke', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Hardcoded Connection String', 'CSharp_Best_Coding_Practice_Hardcoded_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Ignoring Method Return', 'CSharp_Best_Coding_Practice_Ignoring_Method_Return', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Leftover Debug Code', 'CSharp_Best_Coding_Practice_Leftover_Debug_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Magic Numbers', 'CSharp_Best_Coding_Practice_Magic_Numbers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Missing XML Validation', 'CSharp_Best_Coding_Practice_Missing_XML_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Non Private Static Constructors', 'CSharp_Best_Coding_Practice_Non_Private_Static_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: NULL Argument to Equals', 'CSharp_Best_Coding_Practice_NULL_Argument_to_Equals', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Overly Broad Catch', 'CSharp_Best_Coding_Practice_Overly_Broad_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Pages Without Global Error Handler', 'CSharp_Best_Coding_Practice_Pages_Without_Global_Error_Handler', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: PersistSecurityInfo is True', 'CSharp_Best_Coding_Practice_PersistSecurityInfo_is_True', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Single Line If Statement', 'CSharp_Best_Coding_Practice_Single_Line_If_Statement', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Sockets in WebApp', 'CSharp_Best_Coding_Practice_Sockets_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Threads in WebApp', 'CSharp_Best_Coding_Practice_Threads_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Unclosed Objects', 'CSharp_Best_Coding_Practice_Unclosed_Objects', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Uninitialized Variables', 'CSharp_Best_Coding_Practice_Uninitialized_Variables', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Unvalidated Arguments Of Public Methods', 'CSharp_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Use of System Output Stream', 'CSharp_Best_Coding_Practice_Use_of_System_Output_Stream', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Visible Fields', 'CSharp_Best_Coding_Practice_Visible_Fields', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Best Coding Practice: Visible Pointers', 'CSharp_Best_Coding_Practice_Visible_Pointers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic 2nd Order SQL Injection', 'CSharp_Heuristic_Heuristic_2nd_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic DB Paramater Tampering', 'CSharp_Heuristic_Heuristic_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic Parameter Tampering', 'CSharp_Heuristic_Heuristic_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic SQL Injection', 'CSharp_Heuristic_Heuristic_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic Stored XSS', 'CSharp_Heuristic_Heuristic_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Heuristic: Heuristic XSRF', 'CSharp_Heuristic_Heuristic_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Code Injection', 'CSharp_High_Risk_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Command Injection', 'CSharp_High_Risk_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Connection String Injection', 'CSharp_High_Risk_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: LDAP Injection', 'CSharp_High_Risk_LDAP_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Reflected XSS All Clients', 'CSharp_High_Risk_Reflected_XSS_All_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Resource Injection', 'CSharp_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Second Order SQL Injection', 'CSharp_High_Risk_Second_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: SQL injection', 'CSharp_High_Risk_SQL_injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: Stored XSS', 'CSharp_High_Risk_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: UTF7 XSS', 'CSharp_High_Risk_UTF7_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp High Risk: XPath Injection', 'CSharp_High_Risk_XPath_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Blind SQL Injections', 'CSharp_Low_Visibility_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Client Side Only Validation', 'CSharp_Low_Visibility_Client_Side_Only_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Dangerous File Upload', 'CSharp_Low_Visibility_Dangerous_File_Upload', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: DoS by Unreleased Resources', 'CSharp_Low_Visibility_DoS_by_Unreleased_Resources', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Equals without GetHashCode', 'CSharp_Low_Visibility_Equals_without_GetHashCode', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Files Canonicalization Problems', 'CSharp_Low_Visibility_Files_Canonicalization_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Hardcoded Absolute Path', 'CSharp_Low_Visibility_Hardcoded_Absolute_Path', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Hardcoded Password', 'CSharp_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Impersonation Issue', 'CSharp_Low_Visibility_Impersonation_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Improper Exception Handling', 'CSharp_Low_Visibility_Improper_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Improper Session Management', 'CSharp_Low_Visibility_Improper_Session_Management', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Improper Transaction Handling', 'CSharp_Low_Visibility_Improper_Transaction_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: JavaScript Hhijacking', 'CSharp_Low_Visibility_JavaScript_Hhijacking', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Leaving Temporary Files', 'CSharp_Low_Visibility_Leaving_Temporary_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Log Forgery', 'CSharp_Low_Visibility_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Password Misuse', 'CSharp_Low_Visibility_Password_Misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Personal Info In Cookie', 'CSharp_Low_Visibility_Personal_Info_In_Cookie', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Session Clearing Problems', 'CSharp_Low_Visibility_Session_Clearing_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Session Poisoning', 'CSharp_Low_Visibility_Session_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: Thread Safety Issue', 'CSharp_Low_Visibility_Thread_Safety_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: URL Canonicalization Issue', 'CSharp_Low_Visibility_URL_Canonicalization_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: URL Redirection Attack', 'CSharp_Low_Visibility_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Low Visibility: XSS Evasion Attack', 'CSharp_Low_Visibility_XSS_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Buffer Overflow', 'CSharp_Medium_Threat_Buffer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: CGI XSS', 'CSharp_Medium_Threat_CGI_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Data Filter Injection', 'CSharp_Medium_Threat_Data_Filter_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: DB Paramater Tampering', 'CSharp_Medium_Threat_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: DoS by Sleep', 'CSharp_Medium_Threat_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Files Manipulation', 'CSharp_Medium_Threat_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Hardcoded Cryptographic Keys', 'CSharp_Medium_Threat_Hardcoded_Cryptographic_Keys', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Hardcoded password in Connection String', 'CSharp_Medium_Threat_Hardcoded_password_in_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: HttpSplitting', 'CSharp_Medium_Threat_HttpSplitting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Integer Overflow', 'CSharp_Medium_Threat_Integer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Mutex Problem', 'CSharp_Medium_Threat_Mutex_Problem', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Parameter Tampering', 'CSharp_Medium_Threat_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Privacy Violation', 'CSharp_Medium_Threat_Privacy_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Reflected XSS Specific Clients', 'CSharp_Medium_Threat_Reflected_XSS_Specific_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: SQL Injection Evasion Attack', 'CSharp_Medium_Threat_SQL_Injection_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Trust Boundary Violation', 'CSharp_Medium_Threat_Trust_Boundary_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Unclosed Connection', 'CSharp_Medium_Threat_Unclosed_Connection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: Verbose Error Reporting', 'CSharp_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Medium Threat: XSRF', 'CSharp_Medium_Threat_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Avg methods per class', 'CSharp_Metrics_Avg_methods_per_class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Avg statements per Method', 'CSharp_Metrics_Avg_statements_per_Method', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Lines of Code', 'CSharp_Metrics_Lines_of_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of Classes', 'CSharp_Metrics_Number_of_Classes', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of Constructors', 'CSharp_Metrics_Number_of_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of Control Statements', 'CSharp_Metrics_Number_of_Control_Statements', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of Interfaces', 'CSharp_Metrics_Number_of_Interfaces', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of Methods', 'CSharp_Metrics_Number_of_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp Metrics: Number of types', 'CSharp_Metrics_Number_of_types', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: CookieLess', 'CSharp_WebConfig_CookieLess', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: CustomError', 'CSharp_WebConfig_CustomError', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: DebugEnabled', 'CSharp_WebConfig_DebugEnabled', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: HardcodedCredentials', 'CSharp_WebConfig_HardcodedCredentials', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: HttpOnlyCookies XSS', 'CSharp_WebConfig_HttpOnlyCookies_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: NonUniqueFormName', 'CSharp_WebConfig_NonUniqueFormName', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: RequireSSL', 'CSharp_WebConfig_RequireSSL', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: SlidingExpiration', 'CSharp_WebConfig_SlidingExpiration', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CSharp WebConfig: TraceEnabled', 'CSharp_WebConfig_TraceEnabled', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client DoS By Sleep', 'JavaScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Unstructured Error Handling', 'JavaScript_Vulnerabilities_Client_Unstructured_Error_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Untrusted Activex', 'JavaScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Cookies Inspection', 'JavaScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Code Injection', 'JavaScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Cookie Poisoning', 'JavaScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM URL Redirection Attack', 'JavaScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSRF', 'JavaScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSS', 'JavaScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Weak Password Authentication', 'JavaScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client DoS By Sleep', 'VbScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client Untrusted Activex', 'VbScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Cookies Inspection', 'VbScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Code Injection', 'VbScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Cookie Poisoning', 'VbScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM URL Redirection Attack', 'VbScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSRF', 'VbScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSS', 'VbScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Weak Password Authentication', 'VbScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);


-- Java Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Call to Thread run', 'Java_Best_Coding_Practice_Call_to_Thread_run', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Catch NullPointerException', 'Java_Best_Coding_Practice_Catch_NullPointerException', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Catch Without General Exception Handling', 'Java_Best_Coding_Practice_Catch_Without_General_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Confusing Naming', 'Java_Best_Coding_Practice_Confusing_Naming', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Dynamic SQL Queries', 'Java_Best_Coding_Practice_Dynamic_SQL_Queries', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Empty Catch', 'Java_Best_Coding_Practice_Empty_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Erroneous String Compare', 'Java_Best_Coding_Practice_Erroneous_String_Compare', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Explicit Call to Finalize', 'Java_Best_Coding_Practice_Explicit_Call_to_Finalize', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: GOTO Statement', 'Java_Best_Coding_Practice_GOTO_Statement', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Hardcoded Connection String', 'Java_Best_Coding_Practice_Hardcoded_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Ignoring Method Return', 'Java_Best_Coding_Practice_Ignoring_Method_Return', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Leftover Debug Code', 'Java_Best_Coding_Practice_Leftover_Debug_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Magic Numbers', 'Java_Best_Coding_Practice_Magic_Numbers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Missing Catch Block', 'Java_Best_Coding_Practice_Missing_Catch_Block', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Missing XML Validation', 'Java_Best_Coding_Practice_Missing_XML_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: No Default Case', 'Java_Best_Coding_Practice_No_Default_Case', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Not Static Final Logger', 'Java_Best_Coding_Practice_Not_Static_Final_Logger', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Omitted Break Statement', 'Java_Best_Coding_Practice_Omitted_Break_Statement', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Overly Broad Catch', 'Java_Best_Coding_Practice_Overly_Broad_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Overly Broad Throws', 'Java_Best_Coding_Practice_Overly_Broad_Throws', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Pages Without Global Error Handler', 'Java_Best_Coding_Practice_Pages_Without_Global_Error_Handler', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Public Applet Fields', 'Java_Best_Coding_Practice_Public_Applet_Fields', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Return Inside Finally', 'Java_Best_Coding_Practice_Return_Inside_Finally', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Single Line If Statement', 'Java_Best_Coding_Practice_Single_Line_If_Statement', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Sockets in WebApp', 'Java_Best_Coding_Practice_Sockets_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Threads in WebApp', 'Java_Best_Coding_Practice_Threads_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Unclosed Objects', 'Java_Best_Coding_Practice_Unclosed_Objects', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Uninitialized Variables', 'Java_Best_Coding_Practice_Uninitialized_Variables', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Use of System Output Stream', 'Java_Best_Coding_Practice_Use_of_System_Output_Stream', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Best Coding Practice: Visible Fields', 'Java_Best_Coding_Practice_Visible_Fields', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java GWT: GWT DOM XSS', 'Java_GWT_GWT_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java GWT: GWT Reflected XSS', 'Java_GWT_GWT_Reflected_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic 2nd Order SQL Injection', 'Java_Heuristic_Heuristic_2nd_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic CGI Stored XSS', 'Java_Heuristic_Heuristic_CGI_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic DB Paramater Tampering', 'Java_Heuristic_Heuristic_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic Parameter Tampering', 'Java_Heuristic_Heuristic_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic SQL Injection', 'Java_Heuristic_Heuristic_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic Stored XSS', 'Java_Heuristic_Heuristic_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Heuristic: Heuristic XSRF', 'Java_Heuristic_Heuristic_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Code Injection', 'Java_High_Risk_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Command Injection', 'Java_High_Risk_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Connection String Injection', 'Java_High_Risk_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: LDAP Injection', 'Java_High_Risk_LDAP_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Reflected XSS All Clients', 'Java_High_Risk_Reflected_XSS_All_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Resource Injection', 'Java_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Second Order SQL Injection', 'Java_High_Risk_Second_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: SQL injection', 'Java_High_Risk_SQL_injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: Stored XSS', 'Java_High_Risk_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: UTF7 XSS', 'Java_High_Risk_UTF7_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java High Risk: XPath Injection', 'Java_High_Risk_XPath_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Blind SQL Injections', 'Java_Low_Visibility_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Cookie not Sent Over SSL', 'Java_Low_Visibility_Cookie_not_Sent_Over_SSL', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: DoS by Unreleased Resources', 'Java_Low_Visibility_DoS_by_Unreleased_Resources', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Equals without GetHashCode', 'Java_Low_Visibility_Equals_without_GetHashCode', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Files Canonicalization Problems', 'Java_Low_Visibility_Files_Canonicalization_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Hardcoded Absolute Path', 'Java_Low_Visibility_Hardcoded_Absolute_Path', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Hardcoded Password', 'Java_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Improper Exception Handling', 'Java_Low_Visibility_Improper_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Improper Session Management', 'Java_Low_Visibility_Improper_Session_Management', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Improper Transaction Handling', 'Java_Low_Visibility_Improper_Transaction_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Leaving Temporary File', 'Java_Low_Visibility_Leaving_Temporary_File', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Log Forgery', 'Java_Low_Visibility_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Password Misuse', 'Java_Low_Visibility_Password_Misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Personal Info In Cookie', 'Java_Low_Visibility_Personal_Info_In_Cookie', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Session Poisoning', 'Java_Low_Visibility_Session_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Singleton HTTPServlet', 'Java_Low_Visibility_Singleton_HTTPServlet', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Thread Safety Issue', 'Java_Low_Visibility_Thread_Safety_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: URL Redirection Attack', 'Java_Low_Visibility_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: UTF7 XSS', 'Java_Low_Visibility_UTF7_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Low Visibility: Weak Cryptographic Algorithm', 'Java_Low_Visibility_Weak_Cryptographic_Algorithm', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Buffer Overflow', 'Java_Medium_Threat_Buffer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: CGI Reflected XSS All Clients', 'Java_Medium_Threat_CGI_Reflected_XSS_All_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: CGI Stored XSS', 'Java_Medium_Threat_CGI_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: DB Paramater Tampering', 'Java_Medium_Threat_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: DoS by Sleep', 'Java_Medium_Threat_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Environment Manipulation', 'Java_Medium_Threat_Environment_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Files Manipulation', 'Java_Medium_Threat_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Hardcoded Cryptographic Keys', 'Java_Medium_Threat_Hardcoded_Cryptographic_Keys', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Hardcoded password in Connection String', 'Java_Medium_Threat_Hardcoded_password_in_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: HttpSplitting', 'Java_Medium_Threat_HttpSplitting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Integer Overflow', 'Java_Medium_Threat_Integer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Kill VM', 'Java_Medium_Threat_Kill_VM', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Mutex Problem', 'Java_Medium_Threat_Mutex_Problem', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Parameter Tampering', 'Java_Medium_Threat_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Privacy Violation', 'Java_Medium_Threat_Privacy_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Spring ModelView Injection', 'Java_Medium_Threat_Spring_ModelView_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: SQL Injection Evasion Attack', 'Java_Medium_Threat_SQL_Injection_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Trust Boundary Violation', 'Java_Medium_Threat_Trust_Boundary_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Unclosed Connection', 'Java_Medium_Threat_Unclosed_Connection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: Verbose Error Reporting', 'Java_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Medium Threat: XSRF', 'Java_Medium_Threat_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Avg methods per class', 'Java_Metrics_Avg_methods_per_class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Avg statements per Method', 'Java_Metrics_Avg_statements_per_Method', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Lines of Code', 'Java_Metrics_Lines_of_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of Classes', 'Java_Metrics_Number_of_Classes', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of Constructors', 'Java_Metrics_Number_of_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of Control Statements', 'Java_Metrics_Number_of_Control_Statements', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of Interfaces', 'Java_Metrics_Number_of_Interfaces', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of Methods', 'Java_Metrics_Number_of_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Metrics: Number of types', 'Java_Metrics_Number_of_types', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Duplicate Struts Config Files', 'Java_Struts_Duplicate_Struts_Config_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Duplicate Struts Validation Files', 'Java_Struts_Duplicate_Struts_Validation_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Duplicate Validation Forms', 'Java_Struts_Duplicate_Validation_Forms', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Erroneous Validate Method', 'Java_Struts_Erroneous_Validate_Method', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Form Does Not Extend Validation Class', 'Java_Struts_Form_Does_Not_Extend_Validation_Class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Form Field Without Validator', 'Java_Struts_Form_Field_Without_Validator', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Non Private Field In ActionForm Class', 'Java_Struts_Non_Private_Field_In_ActionForm_Class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Thread Safety Violation In Action Class', 'Java_Struts_Thread_Safety_Violation_In_Action_Class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Unvalidated Action Form', 'Java_Struts_Unvalidated_Action_Form', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Validation Turned Off', 'Java_Struts_Validation_Turned_Off', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Java Struts: Validator Without Form Field', 'Java_Struts_Validator_Without_Form_Field', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client DoS By Sleep', 'JavaScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Unstructured Error Handling', 'JavaScript_Vulnerabilities_Client_Unstructured_Error_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Untrusted Activex', 'JavaScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Cookies Inspection', 'JavaScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Code Injection', 'JavaScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Cookie Poisoning', 'JavaScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM URL Redirection Attack', 'JavaScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSRF', 'JavaScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSS', 'JavaScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Weak Password Authentication', 'JavaScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);


-- JavaScript Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client DoS By Sleep', 'JavaScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Unstructured Error Handling', 'JavaScript_Vulnerabilities_Client_Unstructured_Error_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Client Untrusted Activex', 'JavaScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Cookies Inspection', 'JavaScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Code Injection', 'JavaScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM Cookie Poisoning', 'JavaScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM URL Redirection Attack', 'JavaScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSRF', 'JavaScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: DOM XSS', 'JavaScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JavaScript Vulnerabilities: Weak Password Authentication', 'JavaScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);


-- Vbnet Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Aptca Methods Call Non Aptca Methods', 'VbNet_Best_Coding_Practice_Aptca_Methods_Call_Non_Aptca_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Catch NullPointerException', 'VbNet_Best_Coding_Practice_Catch_NullPointerException', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Catch Without General Exception Handling', 'VbNet_Best_Coding_Practice_Catch_Without_General_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Dynamic SQL Queries', 'VbNet_Best_Coding_Practice_Dynamic_SQL_Queries', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Empty Catch', 'VbNet_Best_Coding_Practice_Empty_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: GetLastWin32Error Is Not Called After Pinvoke', 'VbNet_Best_Coding_Practice_GetLastWin32Error_Is_Not_Called_After_Pinvoke', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Hardcoded Connection String', 'VbNet_Best_Coding_Practice_Hardcoded_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Ignoring Method Return', 'VbNet_Best_Coding_Practice_Ignoring_Method_Return', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Leftover Debug Code', 'VbNet_Best_Coding_Practice_Leftover_Debug_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Magic Numbers', 'VbNet_Best_Coding_Practice_Magic_Numbers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Missing XML Validation', 'VbNet_Best_Coding_Practice_Missing_XML_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Non Private Static Constructors', 'VbNet_Best_Coding_Practice_Non_Private_Static_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: NULL Argument to Equals', 'VbNet_Best_Coding_Practice_NULL_Argument_to_Equals', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Overly Broad Catch', 'VbNet_Best_Coding_Practice_Overly_Broad_Catch', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Pages Without Global Error Handler', 'VbNet_Best_Coding_Practice_Pages_Without_Global_Error_Handler', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: PersistSecurityInfo is True', 'VbNet_Best_Coding_Practice_PersistSecurityInfo_is_True', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Sockets in WebApp', 'VbNet_Best_Coding_Practice_Sockets_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Threads in WebApp', 'VbNet_Best_Coding_Practice_Threads_in_WebApp', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Unclosed Objects', 'VbNet_Best_Coding_Practice_Unclosed_Objects', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Uninitialized Variables', 'VbNet_Best_Coding_Practice_Uninitialized_Variables', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Unvalidated Arguments Of Public Methods', 'VbNet_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Use of System Output Stream', 'VbNet_Best_Coding_Practice_Use_of_System_Output_Stream', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Visible Fields', 'VbNet_Best_Coding_Practice_Visible_Fields', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Best Coding Practice: Visible Pointers', 'VbNet_Best_Coding_Practice_Visible_Pointers', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic 2nd Order SQL Injection', 'VbNet_Heuristic_Heuristic_2nd_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic DB Paramater Tampering', 'VbNet_Heuristic_Heuristic_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic Parameter Tampering', 'VbNet_Heuristic_Heuristic_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic SQL Injection', 'VbNet_Heuristic_Heuristic_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic Stored XSS', 'VbNet_Heuristic_Heuristic_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Heuristic: Heuristic XSRF', 'VbNet_Heuristic_Heuristic_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Code Injection', 'VbNet_High_Risk_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Command Injection', 'VbNet_High_Risk_Command_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Connection String Injection', 'VbNet_High_Risk_Connection_String_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: LDAP Injection', 'VbNet_High_Risk_LDAP_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Reflected XSS All Clients', 'VbNet_High_Risk_Reflected_XSS_All_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Resource Injection', 'VbNet_High_Risk_Resource_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Second Order SQL Injection', 'VbNet_High_Risk_Second_Order_SQL_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: SQL injection', 'VbNet_High_Risk_SQL_injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: Stored XSS', 'VbNet_High_Risk_Stored_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: UTF7 XSS', 'VbNet_High_Risk_UTF7_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet High Risk: XPath Injection', 'VbNet_High_Risk_XPath_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Blind SQL Injections', 'VbNet_Low_Visibility_Blind_SQL_Injections', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Client Side Only Validation', 'VbNet_Low_Visibility_Client_Side_Only_Validation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Dangerous File Upload', 'VbNet_Low_Visibility_Dangerous_File_Upload', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: DoS by Unreleased Resources', 'VbNet_Low_Visibility_DoS_by_Unreleased_Resources', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Equals without GetHashCode', 'VbNet_Low_Visibility_Equals_without_GetHashCode', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Files Canonicalization Problems', 'VbNet_Low_Visibility_Files_Canonicalization_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Hardcoded Absolute Path', 'VbNet_Low_Visibility_Hardcoded_Absolute_Path', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Hardcoded Password', 'VbNet_Low_Visibility_Hardcoded_Password', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Impersonation Issue', 'VbNet_Low_Visibility_Impersonation_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Improper Exception Handling', 'VbNet_Low_Visibility_Improper_Exception_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Improper Session Management', 'VbNet_Low_Visibility_Improper_Session_Management', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Improper Transaction Handling', 'VbNet_Low_Visibility_Improper_Transaction_Handling', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: JavaScript Hhijacking', 'VbNet_Low_Visibility_JavaScript_Hhijacking', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Leaving Temporary Files', 'VbNet_Low_Visibility_Leaving_Temporary_Files', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Log Forgery', 'VbNet_Low_Visibility_Log_Forgery', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Password Misuse', 'VbNet_Low_Visibility_Password_Misuse', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Personal Info In Cookie', 'VbNet_Low_Visibility_Personal_Info_In_Cookie', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Session Clearing Problems', 'VbNet_Low_Visibility_Session_Clearing_Problems', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Session Poisoning', 'VbNet_Low_Visibility_Session_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: Thread Safety Issue', 'VbNet_Low_Visibility_Thread_Safety_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: URL Canonicalization Issue', 'VbNet_Low_Visibility_URL_Canonicalization_Issue', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: URL Redirection Attack', 'VbNet_Low_Visibility_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Low Visibility: XSS Evasion Attack', 'VbNet_Low_Visibility_XSS_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Buffer Overflow', 'VbNet_Medium_Threat_Buffer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: CGI XSS', 'VbNet_Medium_Threat_CGI_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Data Filter Injection', 'VbNet_Medium_Threat_Data_Filter_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: DB Paramater Tampering', 'VbNet_Medium_Threat_DB_Paramater_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: DoS by Sleep', 'VbNet_Medium_Threat_DoS_by_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Files Manipulation', 'VbNet_Medium_Threat_Files_Manipulation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Hardcoded Cryptographic Keys', 'VbNet_Medium_Threat_Hardcoded_Cryptographic_Keys', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Hardcoded password in Connection String', 'VbNet_Medium_Threat_Hardcoded_password_in_Connection_String', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: HttpSplitting', 'VbNet_Medium_Threat_HttpSplitting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Integer Overflow', 'VbNet_Medium_Threat_Integer_Overflow', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Mutex Problem', 'VbNet_Medium_Threat_Mutex_Problem', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Parameter Tampering', 'VbNet_Medium_Threat_Parameter_Tampering', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Privacy Violation', 'VbNet_Medium_Threat_Privacy_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Reflected XSS Specific Clients', 'VbNet_Medium_Threat_Reflected_XSS_Specific_Clients', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: SQL Injection Evasion Attack', 'VbNet_Medium_Threat_SQL_Injection_Evasion_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Trust Boundary Violation', 'VbNet_Medium_Threat_Trust_Boundary_Violation', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Unclosed Connection', 'VbNet_Medium_Threat_Unclosed_Connection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: Verbose Error Reporting', 'VbNet_Medium_Threat_Verbose_Error_Reporting', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Medium Threat: XSRF', 'VbNet_Medium_Threat_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Avg methods per class', 'VbNet_Metrics_Avg_methods_per_class', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Avg statements per Method', 'VbNet_Metrics_Avg_statements_per_Method', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Lines of Code', 'VbNet_Metrics_Lines_of_Code', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of Classes', 'VbNet_Metrics_Number_of_Classes', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of Constructors', 'VbNet_Metrics_Number_of_Constructors', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of Control Statements', 'VbNet_Metrics_Number_of_Control_Statements', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of Interfaces', 'VbNet_Metrics_Number_of_Interfaces', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of Methods', 'VbNet_Metrics_Number_of_Methods', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet Metrics: Number of types', 'VbNet_Metrics_Number_of_types', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: CookieLess', 'VbNet_WebConfig_CookieLess', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: CustomError', 'VbNet_WebConfig_CustomError', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: DebugEnabled', 'VbNet_WebConfig_DebugEnabled', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: HardcodedCredentials', 'VbNet_WebConfig_HardcodedCredentials', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: HttpOnlyCookies XSS', 'VbNet_WebConfig_HttpOnlyCookies_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: NonUniqueFormName', 'VbNet_WebConfig_NonUniqueFormName', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: RequireSSL', 'VbNet_WebConfig_RequireSSL', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: SlidingExpiration', 'VbNet_WebConfig_SlidingExpiration', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbNet WebConfig: TraceEnabled', 'VbNet_WebConfig_TraceEnabled', @checkmarx_channel_id);


-- VbScript Queries
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client DoS By Sleep', 'VbScript_Vulnerabilities_Client_DoS_By_Sleep', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Client Untrusted Activex', 'VbScript_Vulnerabilities_Client_Untrusted_Activex', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Cookies Inspection', 'VbScript_Vulnerabilities_Cookies_Inspection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Code Injection', 'VbScript_Vulnerabilities_DOM_Code_Injection', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM Cookie Poisoning', 'VbScript_Vulnerabilities_DOM_Cookie_Poisoning', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM URL Redirection Attack', 'VbScript_Vulnerabilities_DOM_URL_Redirection_Attack', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSRF', 'VbScript_Vulnerabilities_DOM_XSRF', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: DOM XSS', 'VbScript_Vulnerabilities_DOM_XSS', @checkmarx_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VbScript Vulnerabilities: Weak Password Authentication', 'VbScript_Vulnerabilities_Weak_Password_Authentication', @checkmarx_channel_id);



-- FindBugs
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('AM: Creates an empty jar file entry', 'AM_CREATES_EMPTY_JAR_FILE_ENTRY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('AM: Creates an empty zip file entry', 'AM_CREATES_EMPTY_ZIP_FILE_ENTRY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Equals method should not assume anything about the type of its argument', 'BC_EQUALS_METHOD_SHOULD_WORK_FOR_ALL_OBJECTS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Random object created and used only once', 'DMI_RANDOM_USED_ONLY_ONCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Check for sign of bitwise operation', 'BIT_SIGNED_CHECK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CN: Class implements Cloneable but does not define or use clone method', 'CN_IDIOM', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CN: clone method does not call super.clone()', 'CN_IDIOM_NO_SUPER_CALL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CN: Class defines clone() but doesn''t implement Cloneable', 'CN_IMPLEMENTS_CLONE_BUT_NOT_CLONEABLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Co: Abstract class defines covariant compareTo() method', 'CO_ABSTRACT_SELF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Co: Covariant compareTo() method defined', 'CO_SELF_NO_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DE: Method might drop exception', 'DE_MIGHT_DROP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DE: Method might ignore exception', 'DE_MIGHT_IGNORE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Don''t use removeAll to clear a collection', 'DMI_USING_REMOVEALL_TO_CLEAR_COLLECTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DP: Classloaders should only be created inside doPrivileged block', 'DP_CREATE_CLASSLOADER_INSIDE_DO_PRIVILEGED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DP: Method invoked that should be only be invoked inside a doPrivileged block', 'DP_DO_INSIDE_DO_PRIVILEGED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes System.exit(...)', 'DM_EXIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes dangerous method runFinalizersOnExit', 'DM_RUN_FINALIZERS_ON_EXIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ES: Comparison of String parameter using == or !=', 'ES_COMPARING_PARAMETER_STRING_WITH_EQ', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ES: Comparison of String objects using == or !=', 'ES_COMPARING_STRINGS_WITH_EQ', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Abstract class defines covariant equals() method', 'EQ_ABSTRACT_SELF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Equals checks for noncompatible operand', 'EQ_CHECK_FOR_OPERAND_NOT_COMPATIBLE_WITH_THIS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Class defines compareTo(...) and uses Object.equals()', 'EQ_COMPARETO_USE_OBJECT_EQUALS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals method fails for subtypes', 'EQ_GETCLASS_AND_CLASS_CONSTANT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Covariant equals() method defined', 'EQ_SELF_NO_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Empty finalizer should be deleted', 'FI_EMPTY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Explicit invocation of finalizer', 'FI_EXPLICIT_INVOCATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer nulls fields', 'FI_FINALIZER_NULLS_FIELDS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer only nulls fields', 'FI_FINALIZER_ONLY_NULLS_FIELDS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer does not call superclass finalizer', 'FI_MISSING_SUPER_CALL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer nullifies superclass finalizer', 'FI_NULLIFY_SUPER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer does nothing but call superclass finalizer', 'FI_USELESS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('GC: Unchecked type in generic call', 'GC_UNCHECKED_TYPE_IN_GENERIC_CALL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Class defines equals() but not hashCode()', 'HE_EQUALS_NO_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Class defines equals() and uses Object.hashCode()', 'HE_EQUALS_USE_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Class defines hashCode() but not equals()', 'HE_HASHCODE_NO_EQUALS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Class defines hashCode() and uses Object.equals()', 'HE_HASHCODE_USE_OBJECT_EQUALS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Class inherits equals() and uses Object.hashCode()', 'HE_INHERITS_EQUALS_USE_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IC: Superclass uses subclass during initialization', 'IC_SUPERCLASS_USES_SUBCLASS_DURING_INITIALIZATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IMSE: Dubious catching of IllegalMonitorStateException', 'IMSE_DONT_CATCH_IMSE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ISC: Needless instantiation of class that only supplies static methods', 'ISC_INSTANTIATE_STATIC_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('It: Iterator next() method can''t throw NoSuchElementException', 'IT_NO_SUCH_ELEMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('J2EE: Store of non serializable object into HttpSession', 'J2EE_STORE_OF_NON_SERIALIZABLE_OBJECT_INTO_SESSION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JCIP: Fields of immutable classes should be final', 'JCIP_FIELD_ISNT_FINAL_IN_IMMUTABLE_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method with Boolean return type returns explicit null', 'NP_BOOLEAN_RETURN_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Clone method may return null', 'NP_CLONE_COULD_RETURN_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: equals() method does not check for null argument', 'NP_EQUALS_SHOULD_HANDLE_NULL_ARGUMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: toString method may return null', 'NP_TOSTRING_COULD_RETURN_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class names should start with an upper case letter', 'NM_CLASS_NAMING_CONVENTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class is not derived from an Exception, even though it is named as such', 'NM_CLASS_NOT_EXCEPTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Confusing method names', 'NM_CONFUSING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Field names should start with a lower case letter', 'NM_FIELD_NAMING_CONVENTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Use of identifier that is a keyword in later versions of Java', 'NM_FUTURE_KEYWORD_USED_AS_IDENTIFIER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Method names should start with a lower case letter', 'NM_METHOD_NAMING_CONVENTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class names shouldn''t shadow simple name of implemented interface', 'NM_SAME_SIMPLE_NAME_AS_INTERFACE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class names shouldn''t shadow simple name of superclass', 'NM_SAME_SIMPLE_NAME_AS_SUPERCLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Very confusing method names (but perhaps intentional)', 'NM_VERY_CONFUSING_INTENTIONAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Method doesn''t override method in superclass due to wrong package for parameter', 'NM_WRONG_PACKAGE_INTENTIONAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ODR: Method may fail to close database resource', 'ODR_OPEN_DATABASE_RESOURCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ODR: Method may fail to close database resource on exception', 'ODR_OPEN_DATABASE_RESOURCE_EXCEPTION_PATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('OS: Method may fail to close stream', 'OS_OPEN_STREAM', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('OS: Method may fail to close stream on exception', 'OS_OPEN_STREAM_EXCEPTION_PATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RC: Suspicious reference comparison to constant', 'RC_REF_COMPARISON_BAD_PRACTICE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RC: Suspicious reference comparison of Boolean values', 'RC_REF_COMPARISON_BAD_PRACTICE_BOOLEAN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RR: Method ignores results of InputStream.read()', 'RR_NOT_CHECKED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RR: Method ignores results of InputStream.skip()', 'SR_NOT_CHECKED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Method ignores exceptional return value', 'RV_RETURN_VALUE_IGNORED_BAD_PRACTICE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SI: Static initializer creates instance before all static final fields assigned', 'SI_INSTANCE_BEFORE_FINALS_ASSIGNED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SW: Certain swing methods needs to be invoked in Swing thread', 'SW_SWING_METHODS_INVOKED_IN_SWING_THREAD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Non-transient non-serializable instance field in serializable class', 'SE_BAD_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Non-serializable class has a serializable inner class', 'SE_BAD_FIELD_INNER_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Non-serializable value stored into instance field of a serializable class', 'SE_BAD_FIELD_STORE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Comparator doesn''t implement Serializable', 'SE_COMPARATOR_SHOULD_BE_SERIALIZABLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Serializable inner class', 'SE_INNER_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: serialVersionUID isn''t final', 'SE_NONFINAL_SERIALVERSIONID', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: serialVersionUID isn''t long', 'SE_NONLONG_SERIALVERSIONID', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: serialVersionUID isn''t static', 'SE_NONSTATIC_SERIALVERSIONID', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Class is Serializable but its superclass doesn''t define a void constructor', 'SE_NO_SUITABLE_CONSTRUCTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Class is Externalizable but doesn''t define a void constructor', 'SE_NO_SUITABLE_CONSTRUCTOR_FOR_EXTERNALIZATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: The readResolve method must be declared with a return type of Object. ', 'SE_READ_RESOLVE_MUST_RETURN_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Transient field that isn''t set by deserialization. ', 'SE_TRANSIENT_FIELD_NOT_RESTORED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SnVI: Class is Serializable, but doesn''t define serialVersionUID', 'SE_NO_SERIALVERSIONID', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UI: Usage of GetResource may be unsafe if class is extended', 'UI_INHERITANCE_UNSAFE_GETRESOURCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Impossible cast', 'BC_IMPOSSIBLE_CAST', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Impossible downcast', 'BC_IMPOSSIBLE_DOWNCAST', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Impossible downcast of toArray() result', 'BC_IMPOSSIBLE_DOWNCAST_OF_TOARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: instanceof will always return false', 'BC_IMPOSSIBLE_INSTANCEOF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Bitwise add of signed byte value', 'BIT_ADD_OF_SIGNED_BYTE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Incompatible bit masks', 'BIT_AND', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Check to see if ((...) & 0) == 0', 'BIT_AND_ZZ', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Incompatible bit masks', 'BIT_IOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Bitwise OR of signed byte value', 'BIT_IOR_OF_SIGNED_BYTE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BIT: Check for sign of bitwise operation', 'BIT_SIGNED_CHECK_HIGH_BIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BOA: Class overrides a method implemented in super class Adapter wrongly', 'BOA_BADLY_OVERRIDDEN_ADAPTER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BSHIFT: 32 bit int shifted by an amount not in the range 0..31', 'ICAST_BAD_SHIFT_AMOUNT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Primitive value is unboxed and coerced for ternary operator', 'BX_UNBOXED_AND_COERCED_FOR_TERNARY_OPERATOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DLS: Dead store of class literal', 'DLS_DEAD_STORE_OF_CLASS_LITERAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DLS: Overwritten increment', 'DLS_OVERWRITTEN_INCREMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Bad constant value for month', 'DMI_BAD_MONTH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: hasNext method invokes next', 'DMI_CALLING_NEXT_FROM_HASNEXT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Collections should not contain themselves', 'DMI_COLLECTIONS_SHOULD_NOT_CONTAIN_THEMSELVES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Invocation of hashCode on an array', 'DMI_INVOKING_HASHCODE_ON_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Double.longBitsToDouble invoked on an int', 'DMI_LONG_BITS_TO_DOUBLE_INVOKED_ON_INT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Vacuous call to collections', 'DMI_VACUOUS_SELF_COLLECTION_CALL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Can''t use reflection to check for presence of annotation without runtime retention', 'DMI_ANNOTATION_IS_NOT_VISIBLE_TO_REFLECTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Futile attempt to change max pool size of ScheduledThreadPoolExecutor', 'DMI_FUTILE_ATTEMPT_TO_CHANGE_MAXPOOL_SIZE_OF_SCHEDULED_THREAD_POOL_EXECUTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Creation of ScheduledThreadPoolExecutor with zero core threads', 'DMI_SCHEDULED_THREAD_POOL_EXECUTOR_WITH_ZERO_CORE_THREADS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Useless/vacuous call to EasyMock method', 'DMI_VACUOUS_CALL_TO_EASYMOCK_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: equals() used to compare array and nonarray', 'EC_ARRAY_AND_NONARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Invocation of equals() on an array, which is equivalent to ==', 'EC_BAD_ARRAY_COMPARE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: equals(...) used to compare incompatible arrays', 'EC_INCOMPATIBLE_ARRAY_COMPARE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Call to equals() with null argument', 'EC_NULL_ARG', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Call to equals() comparing unrelated class and interface', 'EC_UNRELATED_CLASS_AND_INTERFACE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Call to equals() comparing different interface types', 'EC_UNRELATED_INTERFACES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Call to equals() comparing different types', 'EC_UNRELATED_TYPES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EC: Using pointer equality to compare different types', 'EC_UNRELATED_TYPES_USING_POINTER_EQUALITY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals method always returns false', 'EQ_ALWAYS_FALSE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals method always returns true', 'EQ_ALWAYS_TRUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals method compares class names rather than class objects', 'EQ_COMPARING_CLASS_NAMES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Covariant equals() method defined for enum', 'EQ_DONT_DEFINE_EQUALS_FOR_ENUM', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals() method defined that doesn''t override equals(Object)', 'EQ_OTHER_NO_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals() method defined that doesn''t override Object.equals(Object)', 'EQ_OTHER_USE_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: equals method overrides equals in superclass and may not be symmetric', 'EQ_OVERRIDING_EQUALS_NOT_SYMMETRIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Covariant equals() method defined, Object.equals(Object) inherited', 'EQ_SELF_USE_OBJECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FE: Doomed test for equality to NaN', 'FE_TEST_IF_EQUAL_TO_NOT_A_NUMBER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: Format string placeholder incompatible with passed argument', 'VA_FORMAT_STRING_BAD_ARGUMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: The type of a supplied argument doesn''t match format specifier', 'VA_FORMAT_STRING_BAD_CONVERSION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: MessageFormat supplied where printf style format expected', 'VA_FORMAT_STRING_EXPECTED_MESSAGE_FORMAT_SUPPLIED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: More arguments are passed than are actually used in the format string', 'VA_FORMAT_STRING_EXTRA_ARGUMENTS_PASSED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: Illegal format string', 'VA_FORMAT_STRING_ILLEGAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: Format string references missing argument', 'VA_FORMAT_STRING_MISSING_ARGUMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: No previous argument for format string', 'VA_FORMAT_STRING_NO_PREVIOUS_ARGUMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('GC: No relationship between generic parameter and method argument', 'GC_UNRELATED_TYPES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Signature declares use of unhashable class in hashed construct', 'HE_SIGNATURE_DECLARES_HASHING_OF_UNHASHABLE_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HE: Use of class without a hashCode() method in a hashed data structure', 'HE_USE_OF_UNHASHABLE_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ICAST: integral value cast to double and then passed to Math.ceil', 'ICAST_INT_CAST_TO_DOUBLE_PASSED_TO_CEIL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ICAST: int value cast to float and then passed to Math.round', 'ICAST_INT_CAST_TO_FLOAT_PASSED_TO_ROUND', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: JUnit assertion in run method will not be noticed by JUnit', 'IJU_ASSERT_METHOD_INVOKED_FROM_RUN_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: TestCase declares a bad suite method ', 'IJU_BAD_SUITE_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: TestCase has no tests', 'IJU_NO_TESTS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: TestCase defines setUp that doesn''t call super.setUp()', 'IJU_SETUP_NO_SUPER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: TestCase implements a non-static suite method ', 'IJU_SUITE_NOT_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IJU: TestCase defines tearDown that doesn''t call super.tearDown()', 'IJU_TEARDOWN_NO_SUPER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IL: A collection is added to itself', 'IL_CONTAINER_ADDED_TO_ITSELF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IL: An apparent infinite loop', 'IL_INFINITE_LOOP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IL: An apparent infinite recursive loop', 'IL_INFINITE_RECURSIVE_LOOP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IM: Integer multiply of result of integer remainder', 'IM_MULTIPLYING_RESULT_OF_IREM', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('INT: Bad comparison of nonnegative value with negative constant', 'INT_BAD_COMPARISON_WITH_NONNEGATIVE_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('INT: Bad comparison of signed byte', 'INT_BAD_COMPARISON_WITH_SIGNED_BYTE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IO: Doomed attempt to append to an object output stream', 'IO_APPENDING_TO_OBJECT_OUTPUT_STREAM', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IP: A parameter is dead upon entry to a method but overwritten', 'IP_PARAMETER_IS_DEAD_BUT_OVERWRITTEN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MF: Class defines field that masks a superclass field', 'MF_CLASS_MASKS_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MF: Method defines a variable that obscures a field', 'MF_METHOD_MASKS_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Null pointer dereference', 'NP_ALWAYS_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Null pointer dereference in method on exception path', 'NP_ALWAYS_NULL_EXCEPTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method does not check for null argument', 'NP_ARGUMENT_MIGHT_BE_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: close() invoked on a value that is always null', 'NP_CLOSING_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Null value is guaranteed to be dereferenced', 'NP_GUARANTEED_DEREF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Value is null and guaranteed to be dereferenced on exception path', 'NP_GUARANTEED_DEREF_ON_EXCEPTION_PATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method call passes null to a nonnull parameter ', 'NP_NONNULL_PARAM_VIOLATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method may return null, but is declared @NonNull', 'NP_NONNULL_RETURN_VIOLATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: A known null value is checked to see if it is an instance of a type', 'NP_NULL_INSTANCEOF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Possible null pointer dereference', 'NP_NULL_ON_SOME_PATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Possible null pointer dereference in method on exception path', 'NP_NULL_ON_SOME_PATH_EXCEPTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method call passes null for nonnull parameter', 'NP_NULL_PARAM_DEREF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Method call passes null for nonnull parameter', 'NP_NULL_PARAM_DEREF_ALL_TARGETS_DANGEROUS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Non-virtual method call passes null for nonnull parameter', 'NP_NULL_PARAM_DEREF_NONVIRTUAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Store of null value into field annotated NonNull', 'NP_STORE_INTO_NONNULL_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Read of unwritten field', 'NP_UNWRITTEN_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class defines equal(Object); should it be equals(Object)?', 'NM_BAD_EQUAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class defines hashcode(); should it be hashCode()?', 'NM_LCASE_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Class defines tostring(); should it be toString()?', 'NM_LCASE_TOSTRING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Apparent method/constructor confusion', 'NM_METHOD_CONSTRUCTOR_CONFUSION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Very confusing method names', 'NM_VERY_CONFUSING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Nm: Method doesn''t override method in superclass due to wrong package for parameter', 'NM_WRONG_PACKAGE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('QBA: Method assigns boolean literal in boolean expression', 'QBA_QUESTIONABLE_BOOLEAN_ASSIGNMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RC: Suspicious reference comparison', 'RC_REF_COMPARISON', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RCN: Nullcheck of value previously dereferenced', 'RCN_REDUNDANT_NULLCHECK_WOULD_HAVE_BEEN_A_NPE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RE: Invalid syntax for regular expression', 'RE_BAD_SYNTAX_FOR_REGULAR_EXPRESSION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RE: File.separator used for regular expression', 'RE_CANT_USE_FILE_SEPARATOR_AS_REGULAR_EXPRESSION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RE: "." used for regular expression', 'RE_POSSIBLE_UNINTENDED_PATTERN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Random value from 0 to 1 is coerced to the integer 0', 'RV_01_TO_INT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Bad attempt to compute absolute value of signed 32-bit hashcode ', 'RV_ABSOLUTE_VALUE_OF_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Bad attempt to compute absolute value of signed 32-bit random integer', 'RV_ABSOLUTE_VALUE_OF_RANDOM_INT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Exception created and dropped rather than thrown', 'RV_EXCEPTION_NOT_THROWN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Method ignores return value', 'RV_RETURN_VALUE_IGNORED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RpC: Repeated conditional tests', 'RpC_REPEATED_CONDITIONAL_TEST', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Double assignment of field', 'SA_FIELD_DOUBLE_ASSIGNMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Self assignment of field', 'SA_FIELD_SELF_ASSIGNMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Self comparison of field with itself', 'SA_FIELD_SELF_COMPARISON', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Nonsensical self computation involving a field (e.g., x & x)', 'SA_FIELD_SELF_COMPUTATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Self comparison of value with itself', 'SA_LOCAL_SELF_COMPARISON', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Nonsensical self computation involving a variable (e.g., x & x)', 'SA_LOCAL_SELF_COMPUTATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SF: Dead store due to switch statement fall through', 'SF_DEAD_STORE_DUE_TO_SWITCH_FALLTHROUGH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SF: Dead store due to switch statement fall through to throw', 'SF_DEAD_STORE_DUE_TO_SWITCH_FALLTHROUGH_TO_THROW', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SIC: Deadly embrace of non-static inner class and thread local', 'SIC_THREADLOCAL_DEADLY_EMBRACE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SIO: Unnecessary type check done using instanceof operator', 'SIO_SUPERFLUOUS_INSTANCEOF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL: Method attempts to access a prepared statement parameter with index 0', 'SQL_BAD_PREPARED_STATEMENT_ACCESS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL: Method attempts to access a result set field with index 0', 'SQL_BAD_RESULTSET_ACCESS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STI: Unneeded use of currentThread() call, to call interrupted() ', 'STI_INTERRUPTED_ON_CURRENTTHREAD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STI: Static Thread.interrupted() method invoked on thread instance', 'STI_INTERRUPTED_ON_UNKNOWNTHREAD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Method must be private in order for serialization to work', 'SE_METHOD_MUST_BE_PRIVATE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: The readResolve method must not be declared as a static method. ', 'SE_READ_RESOLVE_IS_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Value annotated as carrying a type qualifier used where a value that must not carry that qualifier is required', 'TQ_ALWAYS_VALUE_USED_WHERE_NEVER_REQUIRED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Value that might not carry a type qualifier is always used in a way requires that type qualifier', 'TQ_MAYBE_SOURCE_VALUE_REACHES_ALWAYS_SINK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Value that might carry a type qualifier is always used in a way prohibits it from having that type qualifier', 'TQ_MAYBE_SOURCE_VALUE_REACHES_NEVER_SINK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Value annotated as never carrying a type qualifier used where value carrying that qualifier is required', 'TQ_NEVER_VALUE_USED_WHERE_ALWAYS_REQUIRED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UMAC: Uncallable method defined in anonymous class', 'UMAC_UNCALLABLE_METHOD_OF_ANONYMOUS_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UR: Uninitialized read of field in constructor', 'UR_UNINIT_READ', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UR: Uninitialized read of field method called from constructor of superclass', 'UR_UNINIT_READ_CALLED_FROM_SUPER_CONSTRUCTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('USELESS_STRING: Invocation of toString on an array', 'DMI_INVOKING_TOSTRING_ON_ANONYMOUS_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('USELESS_STRING: Invocation of toString on an array', 'DMI_INVOKING_TOSTRING_ON_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('USELESS_STRING: Array formatted in useless way using format string', 'VA_FORMAT_STRING_BAD_CONVERSION_FROM_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UwF: Field only ever set to null', 'UWF_NULL_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UwF: Unwritten field', 'UWF_UNWRITTEN_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VA: Primitive array passed to function expecting a variable number of object arguments', 'VA_PRIMITIVE_ARRAY_PASSED_TO_OBJECT_VARARG', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LG: Potential lost logger changes due to weak reference in OpenJDK', 'LG_LOST_LOGGER_DUE_TO_WEAK_REFERENCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('OBL: Method may fail to clean up stream or resource', 'OBL_UNSATISFIED_OBLIGATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Consider using Locale parameterized version of invoked method', 'DM_CONVERT_CASE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EI: May expose internal representation by returning reference to mutable object', 'EI_EXPOSE_REP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('EI2: May expose internal representation by incorporating reference to mutable object', 'EI_EXPOSE_REP2', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FI: Finalizer should be protected, not public', 'FI_PUBLIC_SHOULD_BE_PROTECTED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: May expose internal static state by storing a mutable object into a static field', 'EI_EXPOSE_STATIC_REP2', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field isn''t final and can''t be protected from malicious code', 'MS_CANNOT_BE_FINAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Public static method may expose internal representation by returning array', 'MS_EXPOSE_REP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field should be both final and package protected', 'MS_FINAL_PKGPROTECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field is a mutable array', 'MS_MUTABLE_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field is a mutable Hashtable', 'MS_MUTABLE_HASHTABLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field should be moved out of an interface and made package protected', 'MS_OOI_PKGPROTECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field should be package protected', 'MS_PKGPROTECT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS: Field isn''t final but should be', 'MS_SHOULD_BE_FINAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DC: Possible double check of field', 'DC_DOUBLECHECK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DL: Synchronization on Boolean could lead to deadlock', 'DL_SYNCHRONIZATION_ON_BOOLEAN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DL: Synchronization on boxed primitive could lead to deadlock', 'DL_SYNCHRONIZATION_ON_BOXED_PRIMITIVE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DL: Synchronization on interned String could lead to deadlock', 'DL_SYNCHRONIZATION_ON_SHARED_CONSTANT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DL: Synchronization on boxed primitive values', 'DL_SYNCHRONIZATION_ON_UNSHARED_BOXED_PRIMITIVE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Monitor wait() called on Condition', 'DM_MONITOR_WAIT_ON_CONDITION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: A thread was created using the default empty run method', 'DM_USELESS_THREAD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ESync: Empty synchronized block', 'ESync_EMPTY_SYNC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IS: Inconsistent synchronization', 'IS2_INCONSISTENT_SYNC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IS: Field not guarded against concurrent access', 'IS_FIELD_NOT_GUARDED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('JLM: Synchronization performed on Lock', 'JLM_JSR166_LOCK_MONITORENTER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LI: Incorrect lazy initialization of static field', 'LI_LAZY_INIT_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LI: Incorrect lazy initialization and update of static field', 'LI_LAZY_INIT_UPDATE_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ML: Synchronization on field in futile attempt to guard that field', 'ML_SYNC_ON_FIELD_TO_GUARD_CHANGING_THAT_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ML: Method synchronizes on an updated field', 'ML_SYNC_ON_UPDATED_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MSF: Mutable servlet field', 'MSF_MUTABLE_SERVLET_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MWN: Mismatched notify()', 'MWN_MISMATCHED_NOTIFY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MWN: Mismatched wait()', 'MWN_MISMATCHED_WAIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NN: Naked notify', 'NN_NAKED_NOTIFY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Synchronize and null check on the same field.', 'NP_SYNC_AND_NULL_CHECK_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('No: Using notify() rather than notifyAll()', 'NO_NOTIFY_NOT_NOTIFYALL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RS: Class''s readObject() method is synchronized', 'RS_READOBJECT_SYNC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Return value of putIfAbsent ignored, value passed to putIfAbsent reused', 'RV_RETURN_VALUE_OF_PUTIFABSENT_IGNORED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Ru: Invokes run on a thread (did you mean to start it instead?)', 'RU_INVOKE_RUN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SC: Constructor invokes Thread.start()', 'SC_START_IN_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SP: Method spins on field', 'SP_SPIN_ON_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STCAL: Call to static Calendar', 'STCAL_INVOKE_ON_STATIC_CALENDAR_INSTANCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STCAL: Call to static DateFormat', 'STCAL_INVOKE_ON_STATIC_DATE_FORMAT_INSTANCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STCAL: Static Calendar', 'STCAL_STATIC_CALENDAR_INSTANCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('STCAL: Static DateFormat', 'STCAL_STATIC_SIMPLE_DATE_FORMAT_INSTANCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SWL: Method calls Thread.sleep() with a lock held', 'SWL_SLEEP_WITH_LOCK_HELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TLW: Wait with two locks held', 'TLW_TWO_LOCK_WAIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UG: Unsynchronized get method, synchronized set method', 'UG_SYNC_SET_UNSYNC_GET', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UL: Method does not release lock on all paths', 'UL_UNRELEASED_LOCK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UL: Method does not release lock on all exception paths', 'UL_UNRELEASED_LOCK_EXCEPTION_PATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UW: Unconditional wait', 'UW_UNCOND_WAIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('VO: A volatile reference to an array doesn''t treat the array elements as volatile', 'VO_VOLATILE_REFERENCE_TO_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('WL: Sychronization on getClass rather than class literal', 'WL_USING_GETCLASS_RATHER_THAN_CLASS_LITERAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('WS: Class''s writeObject() method is synchronized but nothing else is', 'WS_WRITEOBJECT_SYNC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Wa: Condition.await() not in loop ', 'WA_AWAIT_NOT_IN_LOOP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Wa: Wait not in loop ', 'WA_NOT_IN_LOOP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Primitive value is boxed and then immediately unboxed', 'BX_BOXING_IMMEDIATELY_UNBOXED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Primitive value is boxed then unboxed to perform primitive coercion', 'BX_BOXING_IMMEDIATELY_UNBOXED_TO_PERFORM_COERCION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Method allocates a boxed primitive just to call toString', 'DM_BOXED_PRIMITIVE_TOSTRING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Method invokes inefficient floating-point Number constructor; use static valueOf instead', 'DM_FP_NUMBER_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Bx: Method invokes inefficient Number constructor; use static valueOf instead', 'DM_NUMBER_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: The equals and hashCode methods of URL are blocking', 'DMI_BLOCKING_METHODS_ON_URL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Maps and sets of URLs can be performance hogs', 'DMI_COLLECTION_OF_URLS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes inefficient Boolean constructor; use Boolean.valueOf(...) instead', 'DM_BOOLEAN_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Explicit garbage collection; extremely dubious except in benchmarking code', 'DM_GC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method allocates an object, only to get the class object', 'DM_NEW_FOR_GETCLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Use the nextInt method of Random rather than nextDouble to generate a random integer', 'DM_NEXTINT_VIA_NEXTDOUBLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes inefficient new String(String) constructor', 'DM_STRING_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes toString() method on a String', 'DM_STRING_TOSTRING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Method invokes inefficient new String() constructor', 'DM_STRING_VOID_CTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HSC: Huge string constants is duplicated across multiple class files', 'HSC_HUGE_SHARED_STRING_CONSTANT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ITA: Method uses toArray() with zero-length array argument', 'ITA_INEFFICIENT_TO_ARRAY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SBSC: Method concatenates strings using + in a loop', 'SBSC_USE_STRINGBUFFER_CONCATENATION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SIC: Should be a static inner class', 'SIC_INNER_SHOULD_BE_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SIC: Could be refactored into a named static inner class', 'SIC_INNER_SHOULD_BE_STATIC_ANON', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SIC: Could be refactored into a static inner class', 'SIC_INNER_SHOULD_BE_STATIC_NEEDS_THIS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SS: Unread field: should this field be static?', 'SS_SHOULD_BE_STATIC', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UM: Method calls static Math class method on a constant value', 'UM_UNNECESSARY_MATH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UPM: Private method is never called', 'UPM_UNCALLED_PRIVATE_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UrF: Unread field', 'URF_UNREAD_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UuF: Unused field', 'UUF_UNUSED_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('WMI: Inefficient use of keySet iterator instead of entrySet iterator', 'WMI_WRONG_MAP_ITERATOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Hardcoded constant database password', 'DMI_CONSTANT_DB_PASSWORD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Empty database password', 'DMI_EMPTY_DB_PASSWORD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HRS: HTTP cookie formed from untrusted input', 'HRS_REQUEST_PARAMETER_TO_COOKIE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HRS: HTTP Response splitting vulnerability', 'HRS_REQUEST_PARAMETER_TO_HTTP_HEADER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL: Nonconstant string passed to execute method on an SQL statement', 'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL: A prepared statement is generated from a nonconstant String', 'SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XSS: JSP reflected cross site scripting vulnerability', 'XSS_REQUEST_PARAMETER_TO_JSP_WRITER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XSS: Servlet reflected cross site scripting vulnerability', 'XSS_REQUEST_PARAMETER_TO_SEND_ERROR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XSS: Servlet reflected cross site scripting vulnerability', 'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Questionable cast to abstract collection ', 'BC_BAD_CAST_TO_ABSTRACT_COLLECTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Questionable cast to concrete collection', 'BC_BAD_CAST_TO_CONCRETE_COLLECTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: Unchecked/unconfirmed cast', 'BC_UNCONFIRMED_CAST', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BC: instanceof will always return true', 'BC_VACUOUS_INSTANCEOF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('BSHIFT: Unsigned right shift cast to short/byte', 'ICAST_QUESTIONABLE_UNSIGNED_RIGHT_SHIFT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CI: Class is final but declares protected field', 'CI_CONFUSED_INHERITANCE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DB: Method uses the same code for two branches', 'DB_DUPLICATE_BRANCHES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DB: Method uses the same code for two switch clauses', 'DB_DUPLICATE_SWITCH_CLAUSES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DLS: Dead store to local variable', 'DLS_DEAD_LOCAL_STORE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DLS: Useless assignment in return statement', 'DLS_DEAD_LOCAL_STORE_IN_RETURN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DLS: Dead store of null to local variable', 'DLS_DEAD_LOCAL_STORE_OF_NULL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Code contains a hard coded reference to an absolute pathname', 'DMI_HARDCODED_ABSOLUTE_FILENAME', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Non serializable object written to ObjectOutput', 'DMI_NONSERIALIZABLE_OBJECT_WRITTEN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('DMI: Invocation of substring(0), which returns the original value', 'DMI_USELESS_SUBSTRING', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Dm: Thread passed where Runnable expected', 'DMI_THREAD_PASSED_WHERE_RUNNABLE_EXPECTED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Class doesn''t override equals in superclass', 'EQ_DOESNT_OVERRIDE_EQUALS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Eq: Unusual equals method ', 'EQ_UNUSUAL', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FE: Test for floating point equality', 'FE_FLOATING_POINT_EQUALITY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('FS: Non-Boolean argument formatted using %b format specifier', 'VA_FORMAT_STRING_BAD_CONVERSION_TO_BOOLEAN', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IA: Ambiguous invocation of either an inherited or outer method', 'IA_AMBIGUOUS_INVOCATION_OF_INHERITED_OR_OUTER_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IC: Initialization circularity', 'IC_INIT_CIRCULARITY', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ICAST: integral division result cast to double or float', 'ICAST_IDIV_CAST_TO_DOUBLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ICAST: Result of integer multiplication cast to long', 'ICAST_INTEGER_MULTIPLY_CAST_TO_LONG', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IM: Computation of average could overflow', 'IM_AVERAGE_COMPUTATION_COULD_OVERFLOW', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IM: Check for oddness that won''t work for negative numbers ', 'IM_BAD_CHECK_FOR_ODD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('INT: Integer remainder modulo 1', 'INT_BAD_REM_BY_1', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('INT: Vacuous comparison of integer value', 'INT_VACUOUS_COMPARISON', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MTIA: Class extends Servlet class and uses instance variables', 'MTIA_SUSPECT_SERVLET_INSTANCE_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MTIA: Class extends Struts Action class and uses instance variables', 'MTIA_SUSPECT_STRUTS_INSTANCE_FIELD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Dereference of the result of readLine() without nullcheck', 'NP_DEREFERENCE_OF_READLINE_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Immediate dereference of the result of readLine()', 'NP_IMMEDIATE_DEREFERENCE_OF_READLINE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Load of known null value', 'NP_LOAD_OF_KNOWN_NULL_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Possible null pointer dereference due to return value of called method', 'NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Possible null pointer dereference on path that might be infeasible', 'NP_NULL_ON_SOME_PATH_MIGHT_BE_INFEASIBLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NP: Parameter must be nonnull but is marked as nullable', 'NP_PARAMETER_MUST_BE_NONNULL_BUT_MARKED_AS_NULLABLE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NS: Potentially dangerous use of non-short-circuit logic', 'NS_DANGEROUS_NON_SHORT_CIRCUIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NS: Questionable use of non-short-circuit logic', 'NS_NON_SHORT_CIRCUIT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('PZLA: Consider returning a zero length array rather than null', 'PZLA_PREFER_ZERO_LENGTH_ARRAYS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('QF: Complicated, subtle or wrong increment in for-loop ', 'QF_QUESTIONABLE_FOR_LOOP', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RCN: Redundant comparison of non-null value to null', 'RCN_REDUNDANT_COMPARISON_OF_NULL_AND_NONNULL_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RCN: Redundant comparison of two null values', 'RCN_REDUNDANT_COMPARISON_TWO_NULL_VALUES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RCN: Redundant nullcheck of value known to be non-null', 'RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RCN: Redundant nullcheck of value known to be null', 'RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('REC: Exception is caught when Exception is not thrown', 'REC_CATCH_EXCEPTION', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RI: Class implements same interface as superclass', 'RI_REDUNDANT_INTERFACES', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Method checks to see if result of String.indexOf is positive', 'RV_CHECK_FOR_POSITIVE_INDEXOF', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Method discards result of readLine after checking if it is nonnull', 'RV_DONT_JUST_NULL_CHECK_READLINE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Remainder of hashCode could be negative', 'RV_REM_OF_HASHCODE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('RV: Remainder of 32-bit signed random integer', 'RV_REM_OF_RANDOM_INT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Double assignment of local variable ', 'SA_LOCAL_DOUBLE_ASSIGNMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SA: Self assignment of local variable', 'SA_LOCAL_SELF_ASSIGNMENT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SF: Switch statement found where one case falls through to the next case', 'SF_SWITCH_FALLTHROUGH', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SF: Switch statement found where default case is missing', 'SF_SWITCH_NO_DEFAULT', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ST: Write to static field from instance method', 'ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: private readResolve method not inherited by subclasses', 'SE_PRIVATE_READ_RESOLVE_NOT_INHERITED', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Se: Transient field of class that isn''t Serializable. ', 'SE_TRANSIENT_FIELD_OF_NONSERIALIZABLE_CLASS', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Explicit annotation inconsistent with use', 'TQ_EXPLICIT_UNKNOWN_SOURCE_VALUE_REACHES_ALWAYS_SINK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TQ: Explicit annotation inconsistent with use', 'TQ_EXPLICIT_UNKNOWN_SOURCE_VALUE_REACHES_NEVER_SINK', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UCF: Useless control flow', 'UCF_USELESS_CONTROL_FLOW', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UCF: Useless control flow to next line', 'UCF_USELESS_CONTROL_FLOW_NEXT_LINE', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('UwF: Field not initialized in constructor', 'UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR', @findbugs_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XFB: Method directly allocates a specific implementation of xml interfaces', 'XFB_XML_FACTORY_BYPASS', @findbugs_channel_id);

-- Orizon

-- AppScanSE

-- AppScan (VERY INCOMPLETE)
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Request Forgery', 'Cross-Site Request Forgery', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Application Error', 'Application Error', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-Site Scripting', 'Cross-Site Scripting', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Microsoft ASP.NET Debugging Enabled', 'Microsoft ASP.NET Debugging Enabled', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Web Application Source Code Disclosure Pattern Found', 'Web Application Source Code Disclosure Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Listing', 'Directory Listing', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Hidden Directory Detected', 'Hidden Directory Detected', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Database Error Pattern Found', 'Database Error Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Unencrypted __VIEWSTATE Parameter', 'Unencrypted __VIEWSTATE Parameter', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection using DECLARE, CAST and EXEC', 'SQL Injection using DECLARE, CAST and EXEC', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Blind SQL Injection', 'Blind SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Unencrypted Login Request', 'Unencrypted Login Request', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Email Address Pattern Found', 'Email Address Pattern Found', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Session Identifier Not Updated', 'Session Identifier Not Updated', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Authentication Bypass Using SQL Injection', 'Authentication Bypass Using SQL Injection', @appscan_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Inadequate Account Lockout', 'Inadequate Account Lockout', @appscan_channel_id);

-- Netsparker
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[High Possibility] SQL Injection', 'HighlyPossibleSqlInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Low Possibility] SQL Injection', 'PossibleSqlInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'ConfirmedSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Blind SQL Injection', 'PossibleBlindSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Blind SQL Injection', 'ConfirmedBlindSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Permanent Cross-site Scripting (XSS)', 'PermanentXSS', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Permanent Cross-site Scripting (XSS)', 'LowPossibilityPermanentXSS', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Basic Authorisation over Clear Text', 'ClearTextBasicAuth', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross-site Scripting', 'XSS', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Cross-site Scripting', 'PossibleXSS', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Ineffective Filtering', 'InactiveXSS', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Internal Server Error', 'InternalServerError', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Auto Complete Enabled', 'AutoCompleteEnabled', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Forbidden Resource', 'ForbiddenResource', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('NTLM Authorization Required', 'NTLMAuthrizationRequired', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Basic Authorization Required', 'BasicAuthorisationRequired', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Digest Authorization Required', 'DigestAuthrizationRequired', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('File Upload Functionality Identified', 'FileUploadFound', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Password Transmitted Over HTTP', 'PasswordOverHTTP', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Critical Form Served Over HTTP', 'PasswordFormOverHTTP', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Internal IP Address Leakage', 'InternalIPLeakage', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cookie Not Marked As Secure', 'CookieNotMarkedAsSecure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cookie Not Marked As HttpOnly', 'CookieNotMarkedAsHttpOnly', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Boolean Based SQL Injection', 'ConfirmedBooleanSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Low Possibility] Boolean Based SQL Injection ', 'PossibleBooleanSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Identified', 'DirectoryFound', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HTTP Header Injection', 'HeaderInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Command Injection', 'CommandInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MySQL 5 Database Identified', 'MySQL5Identified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MySQL 4 Database Identified', 'MySQL4Idenfitied', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MySQL Database Identified', 'MySQLIdenfitied', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Microsoft SQL Server Identified', 'MSSQLIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ORACLE Server Identified', 'ORACLEIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Postgres Server Identified', 'PostgreSQLIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Database User Has Admin Privileges', 'DBConnectedAsAdmin', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[High Possibility] Local File Inclusion', 'HighPossibilityLFI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Local File Inclusion', 'LFI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Local File Inclusion', 'PossibleLocalFileInclusion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Listing (Apache)', 'ApacheDirectoryListing', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Web Server Identified', 'ApacheIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP.NET Version Disclosure', 'ASPNETVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Listing (IIS)', 'IISDirectoryListing', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IIS Identified', 'IISIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Listing (Tomcat)', 'TomcatDirectoryListing', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] PHP Source Code Disclosure', 'PHPSourceCodeDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Generic Source Code Disclosure', 'GenericSourceCodeDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] ASP.NET Source Code Disclosure', 'ASPNETSourceCodeDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] ASP or JSP Source Code Disclosure', 'ASPorJSPSourceCodeDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Internal Path Leakage (Windows)', 'PossibleInternalWindowsPathLeakage', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Possible] Internal Path Leakage (*nix)', 'PossibleInternalUnixPathLeakage', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MS Office Information Disclosure', 'MSOfficeDocumentInformationDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('phpinfo() Information Disclosure', 'PHPInfoIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('E-mail Address Disclosure', 'EmailDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Version Disclosure', 'ApacheVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Tomcat Version Disclosure', 'TomcatVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('PHP Version Disclosure', 'PHPVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('IIS Version Disclosure', 'IISVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Coyote Version Disclosure', 'ApacheCoyoteVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ORACLE Application Server Version Disclosure', 'ORACLEApplicationServerVersion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('OpenSSL Version Disclosure', 'OpenSSLVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Module Version Disclosure', 'ApacheModuleVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Perl Version Disclosure', 'PerlVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Frontpage Version Disclosure', 'FrontPageVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Python Version Disclosure', 'PythonVersionDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP.NET Identified', 'ASPNETIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Sitemap Identified', 'SitemapIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Crossdomain.xml Identified', 'CrossDomainXML', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Open Policy Crossdomain.xml Identified', 'OpenCrossDomainXML', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Robots.txt Identified', 'RobotsIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Server-Status Found', 'ApacheServerStatus', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache Server-Info Found', 'ApacheServerInfo', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[High Possibility] Boolean SQL Injection', 'HighPossibleBooleanSQLInjection', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Database Error Message', 'DatabaseErrorMessages', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Programming Error Message', 'ProgrammingErrorMessages', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Apache MultiViews Enabled', 'ApacheMultiViewsEnabled', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Backup File Found', 'BackupFileFound', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Backup Source Code Found', 'BackupSourceCodeFound', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('TRACE / TRACK Identified', 'TRACETRACKIdentified', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Trace.axd File Found', 'TraceaxdFound', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP.NET Debugging Enabled', 'ASPNETDebugEnabled', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Code Execution via Local File Inclusion', 'LFICodeInclusion', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('htpasswd Disclosure', 'htpasswdDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('htaccess Disclosure', 'htaccessDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ASP.NET Stack Trace Disclosure', 'ASPNETStackTrace', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SVN Disclosure', 'SVNDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('GIT Disclosure', 'GITDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('CVS Disclosure', 'CVSDisclosure', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Remote File Inclusion', 'RFI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Low Possibility] Remote File Inclusion', 'LowPossibilityRFI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('[Low Possibility] Command Injection', 'LowPossibilityCI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XSS via Remote File Inclusion', 'XSSviaRFI', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Remote Code Evaluation (ASP)', 'RCEASP', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Remote Code Evaluation (PHP)', 'RCEPHP', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Static Special Check', 'SpecialCase', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Special Check: Cookie Support Detection', 'SpecialCaseNoCookies', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('MAC is not Enabled in ViewState', 'ViewStateMACNotEnabled', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ViewState is not Encrypted', 'ViewStateNotEncrypted', @netsparker_net_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('ViewState Pre Analyser', 'ViewStateAnalyser', @netsparker_net_channel_id);


-- Sentinel
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross Site Scripting', 'Cross Site Scripting', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SQL Injection', 'SQL Injection', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Traversal', 'Directory Traversal', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('HTTP Response Splitting', 'HTTP Response Splitting', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('XPath Injection', 'XPath Injection', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Predictable Resource Location', 'Predictable Resource Location', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Directory Indexing', 'Directory Indexing', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('LDAP Injection', 'LDAP Injection', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('OS Commanding', 'OS Commanding', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('SSI Injection', 'SSI Injection', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Brute Force', 'Brute Force', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Insufficient Authentication', 'Insufficient Authentication', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Weak Password Recovery Validation', 'Weak Password Recovery Validation', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Credential/Session Prediction', 'Credential/Session Prediction', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Insufficient Session Expiration', 'Insufficient Session Expiration', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Session Fixation', 'Session Fixation', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Cross Site Request Forgery', 'Cross Site Request Forgery', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Information Leakage', 'Information Leakage', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Insufficient Authorization', 'Insufficient Authorization', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Buffer Overflow', 'Buffer Overflow', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Denail of Service', 'Denail of Service', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Content Spoofing', 'Content Spoofing', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Format String Attack', 'Format String Attack', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Abuse of Functionality', 'Abuse of Functionality', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Insufficient Anti-automation', 'Insufficient Anti-automation', @sentinel_channel_id);
INSERT INTO ChannelVulnerability (Name, Code, ChannelTypeId) VALUES ('Insufficient Process Validation', 'Insufficient Process Validation', @sentinel_channel_id);

-- INSERT CHANNEL SEVERITY MAPPINGS --
-- Foritfy

-- CAT.NET
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Process Command Execution'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'File Canonicalization'), @generic_vulnerability_incorrect_behavior_order_validate_before_canonicalize_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Exception Information'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Cross-Site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'Redirection to User Controlled Site'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'XPath Injection'), @generic_vulnerability_failure_to_sanitize_data_within_xpath_expressions_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @cat_net_channel_id AND Name = 'LDAP Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);    
 
-- Checkmarx
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Best_Coding_Practices_Hardcoded_Id'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_High_Risk_Reflected_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_High_Risk_SOQL_SOSL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_High_Risk_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Low_Visibility_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Low_Visibility_Second_Order_SOQL_SOSL_Injection'), @generic_vulnerability_improper_handling_of_windows_device_names_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Medium_Threat_Frame_Spoofing'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Medium_Threat_HttpSplitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Medium_Threat_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Apex_Medium_Threat_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_Client_DoS_By_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_Client_Unstructured_Error_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_Client_Untrusted_Activex'), @generic_vulnerability_exposed_unsafe_activex_method_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_DOM_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_DOM_Cookie_Poisoning'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_DOM_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_DOM_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_DOM_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'JavaScript_Vulnerabilities_Weak_Password_Authentication'), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Catch_NullPointerException'), @generic_vulnerability_use_of_nullpointerexception_catch_to_detect_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Catch_Without_General_Exception_Handling'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Empty_Catch'), @generic_vulnerability_detection_of_error_condition_without_action_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Hardcoded_Connection_String'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Ignoring_Method_Return'), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Missing_XML_Validation'), @generic_vulnerability_missing_xml_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Overly_Broad_Catch'), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Pages_Without_Global_Error_Handler'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Sockets_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_sockets_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Threads_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_threads_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Unclosed_Objects'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Uninitialized_Variables'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods'), @generic_vulnerability_argument_injection_or_modification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_2nd_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Heuristic_Heuristic_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_LDAP_Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Reflected_XSS_All_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Second_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_SQL_injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_UTF7_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_High_Risk_XPath_Injection'), @generic_vulnerability_xml_injection_aka_blind_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Client_Side_Only_Validation'), @generic_vulnerability_client_side_enforcement_of_server_side_securit_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Dangerous_File_Upload'), @generic_vulnerability_unrestricted_upload_of_file_with_dangerous_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_DoS_by_Unreleased_Resources'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Equals_without_GetHashCode'), @generic_vulnerability_object_model_violation_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Files_Canonicalization_Problems'), @generic_vulnerability_improper_limitation_of_a_pathname_to_a_restricted_directory_path_traversal_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Hardcoded_Absolute_Path'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Hardcoded_password_in_Connection_String'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Improper_Exception_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Insecure_Randomness'), @generic_vulnerability_use_of_insufficiently_random_values_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_JavaScript_Hhijacking'), @generic_vulnerability_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Leaving_Temporary_Files'), @generic_vulnerability_temporary_file_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Personal_Info_In_Cookie'), @generic_vulnerability_information_leak_through_persistent_cookies_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_Thread_Safety_Issue'), @generic_vulnerability_unsynchronized_access_to_shared_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_URL_Canonicalization_Issue'), @generic_vulnerability_use_of_non_canonical_url_paths_for_authorization_decisions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Low_Visibility_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Buffer_Overflow'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Hardcoded_Cryptographic_Keys'), @generic_vulnerability_use_of_hard_coded_cryptographic_key_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_HttpSplitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Integer_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Privacy_Violation'), @generic_vulnerability_privacy_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Reflected_XSS_Specific_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_SQL_Injection_Evasion_Attack'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Stored_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Trust_Boundary_Violation'), @generic_vulnerability_trust_boundary_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Unclosed_Connection'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Untrusted_Activex'), @generic_vulnerability_exposed_unsafe_activex_method_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_Medium_Threat_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_CookieLess'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_CustomError'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_DebugEnabled'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_HardcodedCredentials'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_HttpOnlyCookies_XSS'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_NonUniqueFormName'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_RequireSSL'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_SlidingExpiration'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'ASP_WebConfig_TraceEnabled'), @generic_vulnerability_asp.net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_Client_DoS_By_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_Client_Untrusted_Activex'), @generic_vulnerability_exposed_unsafe_activex_method_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_DOM_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_DOM_Cookie_Poisoning'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_DOM_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_DOM_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_DOM_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbScript_Vulnerabilities_Weak_Password_Authentication'), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Empty_Catch'), @generic_vulnerability_detection_of_error_condition_without_action_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Non_Private_Static_Constructors'), @generic_vulnerability_compiler_optimization_removal_or_modification_of_security_critical_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Overly_Broad_Catch'), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Potential_OffByOne_in_Loops'), @generic_vulnerability_off_by_one_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Single_Line_If_Statement'), @generic_vulnerability_incorrect_block_delimitation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods'), @generic_vulnerability_argument_injection_or_modification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Best_Coding_Practice_Use_Of_Goto'), @generic_vulnerability_use_of_potentially_dangerous_function_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_boundedcpy'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_boundedcpy2'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_cin'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_cpycat'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_fgets'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_scanf'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Buffer_Overflow_unbounded'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_Format_String_Attack'), @generic_vulnerability_uncontrolled_format_string_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_MultiByte_String_Length'), @generic_vulnerability_incorrect_calculation_of_multi_byte_string_length_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_OffByOne_arrays'), @generic_vulnerability_off_by_one_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_OffByOne_Loops'), @generic_vulnerability_off_by_one_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_OffByOne_methods'), @generic_vulnerability_off_by_one_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Buffer_Overflow_String_Termination_Error'), @generic_vulnerability_improper_null_termination_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Freed_Pointer_Not_Set_To_Null'), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_2nd_Order_Buffer_Overflow_malloc'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_2nd_Order_Buffer_Overflow_read'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_2nd_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_Buffer_Overflow_malloc'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_Buffer_Overflow_read'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_CGI_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_DB_Parameter_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_NULL_Pointer_Dereference1'), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_NULL_Pointer_Dereference2'), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Heuristic_Heuristic_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_CGI_Reflected_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_CGI_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_Process_Control'), @generic_vulnerability_process_control_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_High_Risk_SQL_injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Boolean_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Char_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Float_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Integer_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Long_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Integer_Overflow_Short_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Arithmenic_Operation_On_Boolean'), @generic_vulnerability_use_of_incorrect_operator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Deprecated_And_Obsolete'), @generic_vulnerability_use_of_obsolete_functions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_DoS_by_Unreleased_Resources'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Hardcoded_Absolute_Path'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Improper_Exception_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Improper_Transaction_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Insecure_Temporary_File'), @generic_vulnerability_insecure_temporary_file_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Leaving_Temporary_Files'), @generic_vulnerability_temporary_file_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Leftover_Debug_Code'), @generic_vulnerability_leftover_debug_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Password_Misuse'), @generic_vulnerability_exposure_of_resource_to_wrong_sphere_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Sizeof_Pointer_Argument'), @generic_vulnerability_use_of_sizeof_on_a_pointer_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Low_Visibility_Stored_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Dangerous_Functions'), @generic_vulnerability_use_of_inherently_dangerous_function_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Double_Free'), @generic_vulnerability_double_free_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Environment_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Hardcoded_Cryptographic_Keys'), @generic_vulnerability_use_of_hard_coded_cryptographic_key_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Hardcoded_password_in_Connection_String'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Heap_Inspection'), @generic_vulnerability_failure_to_clear_heap_memory_before_release_heap_inspection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Improperly_Locked_Memory'), @generic_vulnerability_sensitive_data_storage_in_improperly_locked_memory_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Memory_Leak'), @generic_vulnerability_failure_to_release_memory_before_removing_last_reference_memory_leak_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Setting_Manipulation'), @generic_vulnerability_external_control_of_system_or_configuration_setting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Unchecked_Return_Value'), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Use_After_Free'), @generic_vulnerability_use_after_free_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Use_of_Uninitialized_Variable'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Use_of_Zero_Initialized_Pointer'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Medium_Threat_Wrong_Memory_Allocation'), @generic_vulnerability_uncontrolled_memory_allocation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Second_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_boundcpy'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_cpycat'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_fgets'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Buffer_Overflow_fscanf'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Environment_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Format_String_Attack'), @generic_vulnerability_uncontrolled_format_string_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Process_Control'), @generic_vulnerability_process_control_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CPP_Stored_Vulnerabilities_Stored_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Catch_NullPointerException'), @generic_vulnerability_use_of_nullpointerexception_catch_to_detect_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Catch_Without_General_Exception_Handling'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Empty_Catch'), @generic_vulnerability_detection_of_error_condition_without_action_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Hardcoded_Connection_String'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Ignoring_Method_Return'), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Leftover_Debug_Code'), @generic_vulnerability_leftover_debug_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Missing_XML_Validation'), @generic_vulnerability_missing_xml_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Non_Private_Static_Constructors'), @generic_vulnerability_compiler_optimization_removal_or_modification_of_security_critical_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Overly_Broad_Catch'), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Pages_Without_Global_Error_Handler'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Single_Line_If_Statement'), @generic_vulnerability_incorrect_block_delimitation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Sockets_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_sockets_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Threads_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_threads_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Unclosed_Objects'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Uninitialized_Variables'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods'), @generic_vulnerability_argument_injection_or_modification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_2nd_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_DB_Paramater_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Heuristic_Heuristic_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_LDAP_Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Reflected_XSS_All_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Second_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_SQL_injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_UTF7_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_High_Risk_XPath_Injection'), @generic_vulnerability_xml_injection_aka_blind_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Dangerous_File_Upload'), @generic_vulnerability_unrestricted_upload_of_file_with_dangerous_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_DoS_by_Unreleased_Resources'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Equals_without_GetHashCode'), @generic_vulnerability_object_model_violation_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Files_Canonicalization_Problems'), @generic_vulnerability_improper_limitation_of_a_pathname_to_a_restricted_directory_path_traversal_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Hardcoded_Absolute_Path'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Improper_Exception_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Leaving_Temporary_Files'), @generic_vulnerability_temporary_file_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Personal_Info_In_Cookie'), @generic_vulnerability_information_leak_through_persistent_cookies_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_Thread_Safety_Issue'), @generic_vulnerability_unsynchronized_access_to_shared_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_URL_Canonicalization_Issue'), @generic_vulnerability_use_of_non_canonical_url_paths_for_authorization_decisions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Low_Visibility_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Buffer_Overflow'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_CGI_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Data_Filter_Injection'), @generic_vulnerability_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Hardcoded_Cryptographic_Keys'), @generic_vulnerability_use_of_hard_coded_cryptographic_key_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Hardcoded_password_in_Connection_String'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_HttpSplitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Integer_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Privacy_Violation'), @generic_vulnerability_privacy_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Reflected_XSS_Specific_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_SQL_Injection_Evasion_Attack'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Trust_Boundary_Violation'), @generic_vulnerability_trust_boundary_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Unclosed_Connection'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_Medium_Threat_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_CookieLess'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_CustomError'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_DebugEnabled'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_HardcodedCredentials'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_HttpOnlyCookies_XSS'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_NonUniqueFormName'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_RequireSSL'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_SlidingExpiration'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'CSharp_WebConfig_TraceEnabled'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Call_to_Thread_run'), @generic_vulnerability_call_to_thread_run_instead_of_start_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Catch_NullPointerException'), @generic_vulnerability_use_of_nullpointerexception_catch_to_detect_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Catch_Without_General_Exception_Handling'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Confusing_Naming'), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Empty_Catch'), @generic_vulnerability_detection_of_error_condition_without_action_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Erroneous_String_Compare'), @generic_vulnerability_use_of_wrong_operator_in_string_comparison_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Explicit_Call_to_Finalize'), @generic_vulnerability_explicit_call_to_finalize_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Hardcoded_Connection_String'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Ignoring_Method_Return'), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Leftover_Debug_Code'), @generic_vulnerability_leftover_debug_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Missing_Catch_Block'), @generic_vulnerability_uncaught_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Missing_XML_Validation'), @generic_vulnerability_missing_xml_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_No_Default_Case'), @generic_vulnerability_missing_default_case_in_switch_statement_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Omitted_Break_Statement'), @generic_vulnerability_omitted_break_statement_in_switch_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Overly_Broad_Catch'), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Overly_Broad_Throws'), @generic_vulnerability_declaration_of_throws_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Pages_Without_Global_Error_Handler'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Public_Applet_Fields'), @generic_vulnerability_critical_public_variable_without_final_modifier_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Return_Inside_Finally'), @generic_vulnerability_return_inside_finally_block_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Single_Line_If_Statement'), @generic_vulnerability_incorrect_block_delimitation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Sockets_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_sockets_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Threads_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_threads_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Unclosed_Objects'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Best_Coding_Practice_Uninitialized_Variables'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_GWT_GWT_DOM_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_GWT_GWT_Reflected_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_2nd_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_CGI_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Heuristic_Heuristic_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_LDAP_Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Reflected_XSS_All_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Second_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_SQL_injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_UTF7_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_High_Risk_XPath_Injection'), @generic_vulnerability_xml_injection_aka_blind_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Cookie_not_Sent_Over_SSL'), @generic_vulnerability_sensitive_cookie_in_https_session_without_secure_attribute_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_DoS_by_Unreleased_Resources'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Equals_without_GetHashCode'), @generic_vulnerability_object_model_violation_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Files_Canonicalization_Problems'), @generic_vulnerability_improper_limitation_of_a_pathname_to_a_restricted_directory_path_traversal_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Hardcoded_Absolute_Path'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Improper_Exception_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Leaving_Temporary_File'), @generic_vulnerability_temporary_file_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Personal_Info_In_Cookie'), @generic_vulnerability_information_leak_through_persistent_cookies_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Singleton_HTTPServlet'), @generic_vulnerability_data_leak_between_sessions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Thread_Safety_Issue'), @generic_vulnerability_unsynchronized_access_to_shared_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_UTF7_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Low_Visibility_Weak_Cryptographic_Algorithm'), @generic_vulnerability_use_of_a_broken_or_risky_cryptographic_algorithm_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Buffer_Overflow'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_CGI_Reflected_XSS_All_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_CGI_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Environment_Manipulation'), @generic_vulnerability_external_control_of_system_or_configuration_setting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Hardcoded_Cryptographic_Keys'), @generic_vulnerability_use_of_hard_coded_cryptographic_key_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Hardcoded_password_in_Connection_String'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_HttpSplitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Integer_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Kill_VM'), @generic_vulnerability_j2ee_bad_practices_use_of_system.exit_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Privacy_Violation'), @generic_vulnerability_privacy_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_SQL_Injection_Evasion_Attack'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Trust_Boundary_Violation'), @generic_vulnerability_trust_boundary_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Unclosed_Connection'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Medium_Threat_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Duplicate_Struts_Config_Files'), @generic_vulnerability_technology_specific_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Duplicate_Struts_Validation_Files'), @generic_vulnerability_technology_specific_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Duplicate_Validation_Forms'), @generic_vulnerability_struts_duplicate_validation_forms_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Erroneous_Validate_Method'), @generic_vulnerability_struts_incomplete_validate_method_definition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Form_Does_Not_Extend_Validation_Class'), @generic_vulnerability_struts_form_bean_does_not_extend_validation_class_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Form_Field_Without_Validator'), @generic_vulnerability_struts_form_field_without_validator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Non_Private_Field_In_ActionForm_Class'), @generic_vulnerability_struts_non_private_field_in_actionform_class_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Thread_Safety_Violation_In_Action_Class'), @generic_vulnerability_unsynchronized_access_to_shared_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Unvalidated_Action_Form'), @generic_vulnerability_struts_unvalidated_action_form_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Validation_Turned_Off'), @generic_vulnerability_struts_validator_turned_off_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'Java_Struts_Validator_Without_Form_Field'), @generic_vulnerability_struts_validator_without_form_field_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Catch_NullPointerException'), @generic_vulnerability_use_of_nullpointerexception_catch_to_detect_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Catch_Without_General_Exception_Handling'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Empty_Catch'), @generic_vulnerability_detection_of_error_condition_without_action_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Hardcoded_Connection_String'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Ignoring_Method_Return'), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Leftover_Debug_Code'), @generic_vulnerability_leftover_debug_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Missing_XML_Validation'), @generic_vulnerability_missing_xml_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Non_Private_Static_Constructors'), @generic_vulnerability_compiler_optimization_removal_or_modification_of_security_critical_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Overly_Broad_Catch'), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Pages_Without_Global_Error_Handler'), @generic_vulnerability_error_handling_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Sockets_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_sockets_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Threads_in_WebApp'), @generic_vulnerability_j2ee_bad_practices_direct_use_of_threads_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Unclosed_Objects'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Uninitialized_Variables'), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Best_Coding_Practice_Unvalidated_Arguments_Of_Public_Methods'), @generic_vulnerability_argument_injection_or_modification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_2nd_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Heuristic_Heuristic_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Code_Injection'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Command_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Connection_String_Injection'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_LDAP_Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Reflected_XSS_All_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Resource_Injection'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Second_Order_SQL_Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_SQL_injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_Stored_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_UTF7_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_High_Risk_XPath_Injection'), @generic_vulnerability_xml_injection_aka_blind_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Blind_SQL_Injections'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Client_Side_Only_Validation'), @generic_vulnerability_client_side_enforcement_of_server_side_security_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Dangerous_File_Upload'), @generic_vulnerability_unrestricted_upload_of_file_with_dangerous_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_DoS_by_Unreleased_Resources'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Equals_without_GetHashCode'), @generic_vulnerability_object_model_violation_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Files_Canonicalization_Problems'), @generic_vulnerability_improper_limitation_of_a_pathname_to_a_restricted_directory_path_traversal_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Hardcoded_Absolute_Path'), @generic_vulnerability_use_of_hard_coded_security_relevant_constants_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Hardcoded_Password'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Improper_Exception_Handling'), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Leaving_Temporary_Files'), @generic_vulnerability_temporary_file_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Log_Forgery'), @generic_vulnerability_improper_output_sanitization_for_logs_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Personal_Info_In_Cookie'), @generic_vulnerability_information_leak_through_persistent_cookies_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_Thread_Safety_Issue'), @generic_vulnerability_unsynchronized_access_to_shared_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_URL_Canonicalization_Issue'), @generic_vulnerability_use_of_non_canonical_url_paths_for_authorization_decisions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Low_Visibility_URL_Redirection_Attack'), @generic_vulnerability_url_redirection_to_untrusted_site_open_redirect_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Buffer_Overflow'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_CGI_XSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Data_Filter_Injection'), @generic_vulnerability_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_DB_Paramater_Tampering'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_DoS_by_Sleep'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Files_Manipulation'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Hardcoded_Cryptographic_Keys'), @generic_vulnerability_use_of_hard_coded_cryptographic_key_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Hardcoded_password_in_Connection_String'), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_HttpSplitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Integer_Overflow'), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Parameter_Tampering'), @generic_vulnerability_external_control_of_assumed_immutable_web_parameter_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Privacy_Violation'), @generic_vulnerability_privacy_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Reflected_XSS_Specific_Clients'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_SQL_Injection_Evasion_Attack'), @generic_vulnerability_improper_input_validation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Trust_Boundary_Violation'), @generic_vulnerability_trust_boundary_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Unclosed_Connection'), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_Verbose_Error_Reporting'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_Medium_Threat_XSRF'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_CookieLess'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_CustomError'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_DebugEnabled'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_HardcodedCredentials'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_HttpOnlyCookies_XSS'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_NonUniqueFormName'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_RequireSSL'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_SlidingExpiration'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @checkmarx_channel_id AND Code = 'VbNet_WebConfig_TraceEnabled'), @generic_vulnerability_configuration_id);

-- FindBugs
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "AM: Creates an empty jar file entry"), @generic_vulnerability_failure_to_fulfill_api_contract_api_abuse_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "AM: Creates an empty zip file entry"), @generic_vulnerability_failure_to_fulfill_api_contract_api_abuse_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Equals method should not assume anything about the type of its argument"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Random object created and used only once"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Check for sign of bitwise operation"), @generic_vulnerability_use_of_incorrect_operator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "CN: Class implements Cloneable but does not define or use clone method"), @generic_vulnerability_clone_method_without_super_clone_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "CN: clone method does not call super.clone()"), @generic_vulnerability_clone_method_without_super_clone_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "CN: Class defines clone() but doesn't implement Cloneable"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Co: Abstract class defines covariant compareTo() method"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Co: Covariant compareTo() method defined"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DE: Method might drop exception"), @generic_vulnerability_unchecked_error_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DE: Method might ignore exception"), @generic_vulnerability_unchecked_error_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Don't use removeAll to clear a collection"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DP: Classloaders should only be created inside doPrivileged block"), @generic_vulnerability_protection_mechanism_failure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DP: Method invoked that should be only be invoked inside a doPrivileged block"), @generic_vulnerability_protection_mechanism_failure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes System.exit(...)"), @generic_vulnerability_use_of_system_exit_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes dangerous method runFinalizersOnExit"), @generic_vulnerability_use_of_inherently_dangerous_function_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ES: Comparison of String parameter using == or !="), @generic_vulnerability_use_of_wrong_operator_in_string_comparison_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ES: Comparison of String objects using == or !="), @generic_vulnerability_use_of_wrong_operator_in_string_comparison_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Abstract class defines covariant equals() method"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Equals checks for noncompatible operand"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Class defines compareTo(...) and uses Object.equals()"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals method fails for subtypes"), @generic_vulnerability_comparison_of_classes_by_name_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Covariant equals() method defined"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Empty finalizer should be deleted"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Explicit invocation of finalizer"), @generic_vulnerability_explicit_call_to_finalize_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer nulls fields"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer only nulls fields"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer does not call superclass finalizer"), @generic_vulnerability_finalize_method_without_super_finalize_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer nullifies superclass finalizer"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer does nothing but call superclass finalizer"), @generic_vulnerability_duplicate_operations_on_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "GC: Unchecked type in generic call"), @generic_vulnerability_function_call_with_incorrect_argument_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Class defines equals() but not hashCode()"), @generic_vulnerability_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Class defines equals() and uses Object.hashCode()"), @generic_vulnerability_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Class defines hashCode() but not equals()"), @generic_vulnerability_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Class defines hashCode() and uses Object.equals()"), @generic_vulnerability_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Class inherits equals() and uses Object.hashCode()"), @generic_vulnerability_just_one_of_equals_and_hashcode_defined_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IC: Superclass uses subclass during initialization"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IMSE: Dubious catching of IllegalMonitorStateException"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ISC: Needless instantiation of class that only supplies static methods"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "It: Iterator next() method can't throw NoSuchElementException"), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "J2EE: Store of non serializable object into HttpSession"), @generic_vulnerability_non_serializable_object_stored_in_session_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "JCIP: Fields of immutable classes should be final"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method with Boolean return type returns explicit null"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Clone method may return null"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: equals() method does not check for null argument"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: toString method may return null"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class names should start with an upper case letter"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class is not derived from an Exception"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Confusing method names"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Field names should start with a lower case letter"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Use of identifier that is a keyword in later versions of Java"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Method names should start with a lower case letter"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class names shouldn't shadow simple name of implemented interface"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class names shouldn't shadow simple name of superclass"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Very confusing method names (but perhaps intentional)"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ODR: Method may fail to close database resource"), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ODR: Method may fail to close database resource on exception"), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "OS: Method may fail to close stream"), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "OS: Method may fail to close stream on exception"), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RC: Suspicious reference comparison to constant"), @generic_vulnerability_use_of_incorrect_operator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RC: Suspicious reference comparison of Boolean values"), @generic_vulnerability_use_of_incorrect_operator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RR: Method ignores results of InputStream.read()"), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RR: Method ignores results of InputStream.skip()"), @generic_vulnerability_unchecked_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Method ignores exceptional return value"), @generic_vulnerability_unexpected_status_code_or_return_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SI: Static initializer creates instance before all static final fields assigned"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SW: Certain swing methods needs to be invoked in Swing thread"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Non-transient non-serializable instance field in serializable class"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Non-serializable class has a serializable inner class"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Non-serializable value stored into instance field of a serializable class"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Comparator doesn't implement Serializable"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Serializable inner class"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: serialVersionUID isn't final"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: serialVersionUID isn't long"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: serialVersionUID isn't static"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Class is Serializable but its superclass doesn't define a void constructor"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Class is Externalizable but doesn't define a void constructor"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: The readResolve method must be declared with a return type of Object. "), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Transient field that isn't set by deserialization. "), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SnVI: Class is Serializable"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UI: Usage of GetResource may be unsafe if class is extended"), @generic_vulnerability_use_of_potentially_dangerous_function_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Impossible cast"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Impossible downcast"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Impossible downcast of toArray() result"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: instanceof will always return false"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Bitwise add of signed byte value"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Incompatible bit masks"), @generic_vulnerability_incompatible_bit_masks_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Check to see if ((...) & 0) == 0"), @generic_vulnerability_check_to_see_if_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Incompatible bit masks"), @generic_vulnerability_incompatible_bit_masks_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Bitwise OR of signed byte value"), @generic_vulnerability_bitwise_or_of_signed_byte_value_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BIT: Check for sign of bitwise operation"), @generic_vulnerability_check_for_sign_of_bitwise_operation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BOA: Class overrides a method implemented in super class Adapter wrongly"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BSHIFT: 32 bit int shifted by an amount not in the range 0..31"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Primitive value is unboxed and coerced for ternary operator"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DLS: Dead store of class literal"), @generic_vulnerability_unused_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DLS: Overwritten increment"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Bad constant value for month"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: hasNext method invokes next"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Collections should not contain themselves"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Invocation of hashCode on an array"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Double.longBitsToDouble invoked on an int"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Vacuous call to collections"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Can't use reflection to check for presence of annotation without runtime retention"), @generic_vulnerability_cant_use_reflection_to_check_for_presence_of_annotation_without_runtime_retention_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Futile attempt to change max pool size of ScheduledThreadPoolExecutor"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Creation of ScheduledThreadPoolExecutor with zero core threads"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Useless/vacuous call to EasyMock method"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: equals() used to compare array and nonarray"), @generic_vulnerability_comparison_of_object_references_instead_of_object_contents_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Invocation of equals() on an array"), @generic_vulnerability_comparison_of_object_references_instead_of_object_contents_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: equals(...) used to compare incompatible arrays"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Call to equals() with null argument"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Call to equals() comparing unrelated class and interface"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Call to equals() comparing different interface types"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Call to equals() comparing different types"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EC: Using pointer equality to compare different types"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals method always returns false"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals method always returns true"), @generic_vulnerability_expression_is_always_true_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals method compares class names rather than class objects"), @generic_vulnerability_comparison_of_classes_by_name_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Covariant equals() method defined for enum"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals() method defined that doesn't override equals(Object)"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals() method defined that doesn't override Object.equals(Object)"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: equals method overrides equals in superclass and may not be symmetric"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Covariant equals() method defined"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FE: Doomed test for equality to NaN"), @generic_vulnerability_expression_is_always_false_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: Format string placeholder incompatible with passed argument"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: The type of a supplied argument doesn't match format specifier"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: MessageFormat supplied where printf style format expected"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: More arguments are passed than are actually used in the format string"), @generic_vulnerability_function_call_with_incorrect_number_of_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: Illegal format string"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: Format string references missing argument"), @generic_vulnerability_function_call_with_incorrect_number_of_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: No previous argument for format string"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "GC: No relationship between generic parameter and method argument"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Signature declares use of unhashable class in hashed construct"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HE: Use of class without a hashCode() method in a hashed data structure"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ICAST: integral value cast to double and then passed to Math.ceil"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ICAST: int value cast to float and then passed to Math.round"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: JUnit assertion in run method will not be noticed by JUnit"), @generic_vulnerability_junit_assertion_in_run_method_will_not_be_noticed_by_junit_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: TestCase declares a bad suite method "), @generic_vulnerability_testcase_declares_a_bad_suite_method__id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: TestCase has no tests"), @generic_vulnerability_testcase_has_no_tests_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: TestCase defines setUp that doesn't call super.setUp()"), @generic_vulnerability_testcase_defines_setup_that_doesnt_call_super_setup_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: TestCase implements a non-static suite method "), @generic_vulnerability_testcase_implements_a_non_static_suite_method__id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IJU: TestCase defines tearDown that doesn't call super.tearDown()"), @generic_vulnerability_testcase_defines_teardown_that_doesnt_call_super_teardown_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IL: A collection is added to itself"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IL: An apparent infinite loop"), @generic_vulnerability_unchecked_input_for_loop_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IL: An apparent infinite recursive loop"), @generic_vulnerability_uncontrolled_recursion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IM: Integer multiply of result of integer remainder"), @generic_vulnerability_operator_precedence_logic_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "INT: Bad comparison of nonnegative value with negative constant"), @generic_vulnerability_cleansing_canonicalization_and_comparison_errors_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "INT: Bad comparison of signed byte"), @generic_vulnerability_cleansing_canonicalization_and_comparison_errors_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IO: Doomed attempt to append to an object output stream"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IP: A parameter is dead upon entry to a method but overwritten"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MF: Class defines field that masks a superclass field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MF: Method defines a variable that obscures a field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Null pointer dereference"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Null pointer dereference in method on exception path"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method does not check for null argument"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: close() invoked on a value that is always null"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Null value is guaranteed to be dereferenced"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Value is null and guaranteed to be dereferenced on exception path"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method call passes null to a nonnull parameter "), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method may return null"), @generic_vulnerability_return_of_wrong_status_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: A known null value is checked to see if it is an instance of a type"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Possible null pointer dereference"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Possible null pointer dereference in method on exception path"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method call passes null for nonnull parameter"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Method call passes null for nonnull parameter"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Non-virtual method call passes null for nonnull parameter"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Store of null value into field annotated NonNull"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Read of unwritten field"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class defines equal(Object); should it be equals(Object)?"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class defines hashcode(); should it be hashCode()?"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Class defines tostring(); should it be toString()?"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Apparent method/constructor confusion"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Very confusing method names"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Nm: Method doesn't override method in superclass due to wrong package for parameter"), @generic_vulnerability_function_call_with_incorrect_argument_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "QBA: Method assigns boolean literal in boolean expression"), @generic_vulnerability_assigning_instead_of_comparing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RC: Suspicious reference comparison"), @generic_vulnerability_use_of_incorrect_operator_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RCN: Nullcheck of value previously dereferenced"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RE: Invalid syntax for regular expression"), @generic_vulnerability_incorrect_regular_expression_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RE: File.separator used for regular expression"), @generic_vulnerability_incorrect_regular_expression_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RE: . used for regular expression"), @generic_vulnerability_incorrect_regular_expression_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Random value from 0 to 1 is coerced to the integer 0"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Bad attempt to compute absolute value of signed 32-bit hashcode "), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Bad attempt to compute absolute value of signed 32-bit random integer"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Exception created and dropped rather than thrown"), @generic_vulnerability_improper_handling_of_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Method ignores return value"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RpC: Repeated conditional tests"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Double assignment of field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Self assignment of field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Self comparison of field with itself"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Nonsensical self computation involving a field (e.g."), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Self comparison of value with itself"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Nonsensical self computation involving a variable (e.g."), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SF: Dead store due to switch statement fall through"), @generic_vulnerability_omitted_break_statement_in_switch_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SF: Dead store due to switch statement fall through to throw"), @generic_vulnerability_omitted_break_statement_in_switch_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SIC: Deadly embrace of non-static inner class and thread local"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SIO: Unnecessary type check done using instanceof operator"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SQL: Method attempts to access a prepared statement parameter with index 0"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SQL: Method attempts to access a result set field with index 0"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STI: Unneeded use of currentThread() call"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STI: Static Thread.interrupted() method invoked on thread instance"), @generic_vulnerability_direct_use_of_threads_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Method must be private in order for serialization to work"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: The readResolve method must not be declared as a static method. "), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Value annotated as carrying a type qualifier used where a value that must not carry that qualifier is required"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Value that might not carry a type qualifier is always used in a way requires that type qualifier"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Value that might carry a type qualifier is always used in a way prohibits it from having that type qualifier"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Value annotated as never carrying a type qualifier used where value carrying that qualifier is required"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UMAC: Uncallable method defined in anonymous class"), @generic_vulnerability_dead_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UR: Uninitialized read of field in constructor"), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UR: Uninitialized read of field method called from constructor of superclass"), @generic_vulnerability_use_of_uninitialized_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Code = "DMI_INVOKING_TOSTRING_ON_ARRAY"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI_INVOKING_TOSTRING_ON_ANONYMOUS_ARRAY"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "USELESS_STRING: Array formatted in useless way using format string"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UwF: Field only ever set to null"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UwF: Unwritten field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "VA: Primitive array passed to function expecting a variable number of object arguments"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "LG: Potential lost logger changes due to weak reference in OpenJDK"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "OBL: Method may fail to clean up stream or resource"), @generic_vulnerability_improper_resource_shutdown_or_release_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Consider using Locale parameterized version of invoked method"), @generic_vulnerability_encoding_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EI: May expose internal representation by returning reference to mutable object"), @generic_vulnerability_passing_mutable_objects_to_an_untrusted_method_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "EI2: May expose internal representation by incorporating reference to mutable object"), @generic_vulnerability_mutable_objects_passed_by_reference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FI: Finalizer should be protected"), @generic_vulnerability_finalize_method_declared_public_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: May expose internal static state by storing a mutable object into a static field"), @generic_vulnerability_public_static_final_field_references_mutable_object_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field isn't final and can't be protected from malicious code"), @generic_vulnerability_public_static_field_not_marked_final_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Public static method may expose internal representation by returning array"), @generic_vulnerability_passing_mutable_objects_to_an_untrusted_method_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field should be both final and package protected"), @generic_vulnerability_public_static_field_not_marked_final_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field is a mutable array"), @generic_vulnerability_public_static_final_field_references_mutable_object_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field is a mutable Hashtable"), @generic_vulnerability_public_static_final_field_references_mutable_object_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field should be moved out of an interface and made package protected"), @generic_vulnerability_public_static_final_field_references_mutable_object_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field should be package protected"), @generic_vulnerability_exposure_of_resource_to_wrong_sphere_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MS: Field isn't final but should be"), @generic_vulnerability_public_static_field_not_marked_final_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DC: Possible double check of field"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DL: Synchronization on Boolean could lead to deadlock"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DL: Synchronization on boxed primitive could lead to deadlock"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DL: Synchronization on interned String could lead to deadlock"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DL: Synchronization on boxed primitive values"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Monitor wait() called on Condition"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: A thread was created using the default empty run method"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ESync: Empty synchronized block"), @generic_vulnerability_empty_synchronized_block_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IS: Inconsistent synchronization"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IS: Field not guarded against concurrent access"), @generic_vulnerability_race_condition_within_a_thread_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "JLM: Synchronization performed on Lock"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "LI: Incorrect lazy initialization of static field"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "LI: Incorrect lazy initialization and update of static field"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ML: Synchronization on field in futile attempt to guard that field"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ML: Method synchronizes on an updated field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MSF: Mutable servlet field"), @generic_vulnerability_race_condition_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MWN: Mismatched notify()"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MWN: Mismatched wait()"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NN: Naked notify"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Synchronize and null check on the same field."), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "No: Using notify() rather than notifyAll()"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RS: Class's readObject() method is synchronized"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Return value of putIfAbsent ignored"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Ru: Invokes run on a thread (did you mean to start it instead?)"), @generic_vulnerability_call_to_thread_run_instead_of_start_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SC: Constructor invokes Thread.start()"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SP: Method spins on field"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STCAL: Call to static Calendar"), @generic_vulnerability_race_condition_within_a_thread_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STCAL: Call to static DateFormat"), @generic_vulnerability_race_condition_within_a_thread_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STCAL: Static Calendar"), @generic_vulnerability_race_condition_within_a_thread_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "STCAL: Static DateFormat"), @generic_vulnerability_race_condition_within_a_thread_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SWL: Method calls Thread.sleep() with a lock held"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TLW: Wait with two locks held"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UG: Unsynchronized get method"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UL: Method does not release lock on all paths"), @generic_vulnerability_improper_control_of_a_resource_through_its_lifetime_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UL: Method does not release lock on all exception paths"), @generic_vulnerability_improper_control_of_a_resource_through_its_lifetime_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UW: Unconditional wait"), @generic_vulnerability_insufficient_control_flow_management_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "VO: A volatile reference to an array doesn't treat the array elements as volatile"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "WL: Sychronization on getClass rather than class literal"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "WS: Class's writeObject() method is synchronized but nothing else is"), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Wa: Condition.await() not in loop "), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Wa: Wait not in loop "), @generic_vulnerability_insufficient_synchronization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Primitive value is boxed and then immediately unboxed"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Primitive value is boxed then unboxed to perform primitive coercion"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Method allocates a boxed primitive just to call toString"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Method invokes inefficient floating-point Number constructor; use static valueOf instead"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Bx: Method invokes inefficient Number constructor; use static valueOf instead"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: The equals and hashCode methods of URL are blocking"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Maps and sets of URLs can be performance hogs"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes inefficient Boolean constructor; use Boolean.valueOf(...) instead"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Explicit garbage collection; extremely dubious except in benchmarking code"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method allocates an object"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Use the nextInt method of Random rather than nextDouble to generate a random integer"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes inefficient new String(String) constructor"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes toString() method on a String"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Method invokes inefficient new String() constructor"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HSC: Huge string constants is duplicated across multiple class files"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ITA: Method uses toArray() with zero-length array argument"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SBSC: Method concatenates strings using + in a loop"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SIC: Should be a static inner class"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SIC: Could be refactored into a named static inner class"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SIC: Could be refactored into a static inner class"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SS: Unread field: should this field be static?"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UM: Method calls static Math class method on a constant value"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UPM: Private method is never called"), @generic_vulnerability_dead_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UrF: Unread field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UuF: Unused field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "WMI: Inefficient use of keySet iterator instead of entrySet iterator"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Hardcoded constant database password"), @generic_vulnerability_use_of_hard_coded_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Empty database password"), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HRS: HTTP cookie formed from untrusted input"), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "HRS: HTTP Response splitting vulnerability"), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SQL: Nonconstant string passed to execute method on an SQL statement"), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SQL: A prepared statement is generated from a nonconstant String"), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "XSS: JSP reflected cross site scripting vulnerability"), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Code = "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER"), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Code = "XSS_REQUEST_PARAMETER_TO_SEND_ERROR"), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Questionable cast to abstract collection "), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Questionable cast to concrete collection"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: Unchecked/unconfirmed cast"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BC: instanceof will always return true"), @generic_vulnerability_expression_is_always_true_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "BSHIFT: Unsigned right shift cast to short/byte"), @generic_vulnerability_incorrect_type_conversion_or_cast_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "CI: Class is final but declares protected field"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DB: Method uses the same code for two branches"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DB: Method uses the same code for two switch clauses"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DLS: Dead store to local variable"), @generic_vulnerability_unused_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DLS: Useless assignment in return statement"), @generic_vulnerability_unused_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DLS: Dead store of null to local variable"), @generic_vulnerability_unused_variable_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Code contains a hard coded reference to an absolute pathname"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Non serializable object written to ObjectOutput"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "DMI: Invocation of substring(0)"), @generic_vulnerability_expected_behavior_violation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Dm: Thread passed where Runnable expected"), @generic_vulnerability_function_call_with_incorrect_argument_type_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Class doesn't override equals in superclass"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Eq: Unusual equals method "), @generic_vulnerability_incorrect_semantic_object_comparison_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FE: Test for floating point equality"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "FS: Non-Boolean argument formatted using %b format specifier"), @generic_vulnerability_function_call_with_incorrectly_specified_arguments_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IA: Ambiguous invocation of either an inherited or outer method"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IC: Initialization circularity"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ICAST: integral division result cast to double or float"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ICAST: Result of integer multiplication cast to long"), @generic_vulnerability_integer_coercion_error_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IM: Computation of average could overflow"), @generic_vulnerability_integer_overflow_or_wraparound_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "IM: Check for oddness that won't work for negative numbers "), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "INT: Integer remainder modulo 1"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "INT: Vacuous comparison of integer value"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MTIA: Class extends Servlet class and uses instance variables"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "MTIA: Class extends Struts Action class and uses instance variables"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Dereference of the result of readLine() without nullcheck"), @generic_vulnerability_unchecked_return_value_to_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Immediate dereference of the result of readLine()"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Load of known null value"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Possible null pointer dereference due to return value of called method"), @generic_vulnerability_unchecked_return_value_to_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Possible null pointer dereference on path that might be infeasible"), @generic_vulnerability_null_pointer_dereference_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NP: Parameter must be nonnull but is marked as nullable"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NS: Potentially dangerous use of non-short-circuit logic"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "NS: Questionable use of non-short-circuit logic"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "PZLA: Consider returning a zero length array rather than null"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "QF: Complicated"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RCN: Redundant comparison of non-null value to null"), @generic_vulnerability_duplicate_operations_on_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RCN: Redundant comparison of two null values"), @generic_vulnerability_duplicate_operations_on_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RCN: Redundant nullcheck of value known to be non-null"), @generic_vulnerability_duplicate_operations_on_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RCN: Redundant nullcheck of value known to be null"), @generic_vulnerability_duplicate_operations_on_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "REC: Exception is caught when Exception is not thrown"), @generic_vulnerability_declaration_of_catch_for_generic_exception_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RI: Class implements same interface as superclass"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Method checks to see if result of String.indexOf is positive"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Method discards result of readLine after checking if it is nonnull"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Remainder of hashCode could be negative"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "RV: Remainder of 32-bit signed random integer"), @generic_vulnerability_expression_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Double assignment of local variable "), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SA: Self assignment of local variable"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SF: Switch statement found where one case falls through to the next case"), @generic_vulnerability_omitted_break_statement_in_switch_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "SF: Switch statement found where default case is missing"), @generic_vulnerability_missing_default_case_in_switch_statement_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "ST: Write to static field from instance method"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: private readResolve method not inherited by subclasses"), @generic_vulnerability_failure_to_follow_specification_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "Se: Transient field of class that isn't Serializable. "), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Explicit annotation inconsistent with use"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "TQ: Explicit annotation inconsistent with use"), @generic_vulnerability_indicator_of_poor_code_quality_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UCF: Useless control flow"), @generic_vulnerability_always_incorrect_control_flow_implementation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UCF: Useless control flow to next line"), @generic_vulnerability_always_incorrect_control_flow_implementation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "UwF: Field not initialized in constructor"), @generic_vulnerability_improper_initialization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @findbugs_channel_id AND Name = "XFB: Method directly allocates a specific implementation of xml interfaces"), @generic_vulnerability_indicator_of_poor_code_quality_id);

-- AppScanSE


-- AppScan (ALSO VERY INCOMPLETE)
-- the mapping for 'Database Error Pattern Found' is too general.
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Cross-Site Request Forgery'), @generic_vulnerability_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Application Error'), @generic_vulnerability_asp_net_environment_issues_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Cross-Site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Web Application Source Code Disclosure Pattern Found'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Microsoft ASP.NET Debugging Enabled'), @generic_vulnerability_asp_net_misconfiguration_creating_debug_binary_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Directory Listing'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Hidden Directory Detected'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Unencrypted __VIEWSTATE Parameter'), @generic_vulnerability_asp_net_misconfiguration_not_using_input_validation_framework_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'SQL Injection using DECLARE, CAST and EXEC'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Blind SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Unencrypted Login Request'), @generic_vulnerability_missing_encryption_of_sensitive_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Email Address Pattern Found'), @generic_vulnerability_intended_information_leak_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Session Identifier Not Updated'), @generic_vulnerability_insufficient_session_expiration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Authentication Bypass Using SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Inadequate Account Lockout'), @generic_vulnerability_improper_restriction_of_excessive_authentication_attempts_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES ( 1, 
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @appscan_channel_id AND Name = 'Database Error Pattern Found'), @generic_vulnerability_improper_input_validation_id);

-- Netsparker
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[High Possibility] SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Low Possibility] SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Blind SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Blind SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Code = 'PermanentXSS'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Basic Authorisation over Clear Text'), @generic_vulnerability_cleartext_transmission_of_sensitive_information_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Cross-site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Internal Server Error'), @generic_vulnerability_failure_to_handle_exceptional_conditions_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Auto Complete Enabled'), @generic_vulnerability_information_leak_through_browser_caching_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'NTLM Authorization Required'), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Basic Authorization Required'), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Password Transmitted Over HTTP'), @generic_vulnerability_unprotected_transport_of_credentials_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Critical Form Served Over HTTP'), @generic_vulnerability_missing_encryption_of_sensitive_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Internal IP Address Leakage'), @generic_vulnerability_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Cookie Not Marked As Secure'), @generic_vulnerability_sensitive_cookie_in_https_session_without_secure_attribute_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Cookie Not Marked As HttpOnly'), @generic_vulnerability_protection_mechanism_failure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Boolean Based SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Low Possibility] Boolean Based SQL Injection '), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'HTTP Header Injection'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Command Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Database User Has Admin Privileges'), @generic_vulnerability_incorrect_user_management_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[High Possibility] Local File Inclusion'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Local File Inclusion'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Local File Inclusion'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Directory Listing (Apache)'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Web Server Identified'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'ASP.NET Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Directory Listing (IIS)'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Directory Listing (Tomcat)'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] PHP Source Code Disclosure'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Generic Source Code Disclosure'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] ASP.NET Source Code Disclosure'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] ASP or JSP Source Code Disclosure'), @generic_vulnerability_information_leak_through_source_code_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Internal Path Leakage (Windows)'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Possible] Internal Path Leakage (*nix)'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'MS Office Information Disclosure'), @generic_vulnerability_improper_cross_boundary_removal_of_sensitive_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'phpinfo() Information Disclosure'), @generic_vulnerability_information_leak_through_debug_information_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'E-mail Address Disclosure'), @generic_vulnerability_intended_information_leak_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Tomcat Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'PHP Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'IIS Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Coyote Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'ORACLE Application Server Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'OpenSSL Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Module Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Perl Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Frontpage Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Python Version Disclosure'), @generic_vulnerability_information_leak_through_sent_data_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Open Policy Crossdomain.xml Identified'), @generic_vulnerability_incorrect_permission_assignment_for_critical_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Robots.txt Identified'), @generic_vulnerability_incorrect_permission_assignment_for_critical_resource_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Server-Status Found'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache Server-Info Foundpache Server-Info Found'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[High Possibility] Boolean SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Database Error Message'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Programming Error Message'), @generic_vulnerability_information_exposure_through_an_error_message_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Apache MultiViews Enabled'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Backup File Found'), @generic_vulnerability_exposure_of_backup_file_to_an_unauthorized_control_sphere_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Backup Source Code Found'), @generic_vulnerability_exposure_of_backup_file_to_an_unauthorized_control_sphere_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'TRACE / TRACK Identified'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Trace.axd File Found'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'ASP.NET Debugging Enabled'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Code Execution via Local File Inclusion'), @generic_vulnerability_failure_to_sanitize_server_side_includes_ssi_within_a_web_page_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'ASP.NET Stack Trace Disclosure'), @generic_vulnerability_asp_net_misconfiguration_missing_custom_error_page_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'SVN Disclosure'), @generic_vulnerability_file_and_directory_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'GIT Disclosure'), @generic_vulnerability_file_and_directory_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'CVS Disclosure'), @generic_vulnerability_exposure_of_cvs_repository_to_an_unauthorized_control_sphere_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Remote File Inclusion'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Low Possibility] Remote File Inclusion'), @generic_vulnerability_improper_control_of_resource_identifiers_resource_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = '[Low Possibility] Command Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_a_command_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'XSS via Remote File Inclusion'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Remote Code Evaluation (ASP)'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Remote Code Evaluation (PHP)'), @generic_vulnerability_failure_to_control_generation_of_code_code_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'Special Check: Cookie Support Detection'), @generic_vulnerability_cookie_support_detection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'MAC is not Enabled in ViewState'), @generic_vulnerability_configuration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, 
	(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @netsparker_net_channel_id AND Name = 'ViewState is not Encrypted'), @generic_vulnerability_configuration_id);

-- Sentinel
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Cross Site Scripting'), @generic_vulnerability_failure_to_preserve_web_page_structure_cross_site_scripting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'SQL Injection'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_sql_command_sql_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Directory Traversal'), @generic_vulnerability_path_traversal_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'HTTP Response Splitting'), @generic_vulnerability_failure_to_sanitize_crlf_sequences_in_http_headers_http_response_splitting_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'XPath Injection'), @generic_vulnerability_failure_to_sanitize_data_within_xpath_expressions_xpath_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Predictable Resource Location'), @generic_vulnerability_direct_request_forced_browsing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Directory Indexing'), @generic_vulnerability_information_leak_through_directory_listing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'LDAP Injection'), @generic_vulnerability_failure_to_sanitize_data_into_ldap_queries_ldap_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'OS Commanding'), @generic_vulnerability_improper_sanitization_of_special_elements_used_in_an_os_command_os_command_injection_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'SSI Injection'), @generic_vulnerability_failure_to_sanitize_server_side_includes_ssi_within_a_web_page_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Brute Force'), @generic_vulnerability_improper_restriction_of_excessive_authentication_attempts_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Insufficient Authentication'), @generic_vulnerability_improper_authentication_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Weak Password Recovery Validation'), @generic_vulnerability_weak_password_recovery_mechanism_for_forgotten_password_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Credential/Session Prediction'), @generic_vulnerability_predictable_exact_value_from_previous_values_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Insufficient Session Expiration'), @generic_vulnerability_insufficient_session_expiration_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Session Fixation'), @generic_vulnerability_session_fixation_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Cross Site Request Forgery'), @generic_vulnerability_owasp_top_ten_2007_category_a5_cross_site_request_forgery_csrf_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Information Leakage'), @generic_vulnerability_information_exposure_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Insufficient Authorization'), @generic_vulnerability_improper_access_control_authorization_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Buffer Overflow'), @generic_vulnerability_buffer_copy_without_checking_size_of_input_classic_buffer_overflow_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Denail of Service'), @generic_vulnerability_uncontrolled_resource_consumption_resource_exhaustion_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Content Spoofing'), @generic_vulnerability_authentication_bypass_by_spoofing_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Format String Attack'), @generic_vulnerability_uncontrolled_format_string_id);
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Abuse of Functionality'), @generic_vulnerability_intentionally_introduced_weakness_id);
-- INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
--    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Insufficient Anti-automation'), @generic_vulnerability_xxx_id); -- TODO: FIND MATCH IF POSS.
INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1,
    (SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = @sentinel_channel_id AND Name = 'Insufficient Process Validation'), @generic_vulnerability_insufficient_control_flow_management_id);
    
    