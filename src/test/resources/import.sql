insert into organization (name, createdDate, ModifiedDate, active) values ('SRS', now(), now(), 1);
insert into organization (name, createdDate, ModifiedDate, active) values ('Procurement', now(), now(), 1);
insert into organization (name, createdDate, ModifiedDate, active) values ('Denim Group', now(), now(), 1);

insert into application (name, url, OrganizationId, createdDate, ModifiedDate, active) values ('Order Review', 'http://srs/OrderReview', 1, now(), now(), 1);
insert into application (name, url, OrganizationId, createdDate, ModifiedDate, active) values ('Store Walk', 'http://srs/handheld/storewalk', 1, now(), now(), 1);
insert into application (name, url, OrganizationId, createdDate, ModifiedDate, active) values ('Central Inventory', 'http://srs/ci', 1, now(), now(), 1);
insert into application (name, url, OrganizationId, createdDate, ModifiedDate, active) values ('CMIS', 'http://cmis/index.htm', 2, now(), now(), 1);
insert into application (name, url, OrganizationId, createdDate, ModifiedDate, active) values ('DCC', 'http://intranet.heb.com/dcc', 2, now(), now(), 1);

insert into defecttrackertype(name) values ('Bugzilla');
insert into defecttrackertype(name) values ('Jira');

insert into defecttracker(name, url, defecttrackertypeid, createdDate, ModifiedDate, active) values ('Bugzilla_dcc', 'http://www.bugzilla.org/', 1, now(), now(), 1);
insert into defecttracker(name, url, defecttrackertypeid, createdDate, ModifiedDate, active) values ('Jira1', 'http://www.atlassian.com/software/jira/', 2, now(), now(), 1);

insert into defect (nativeId, createdDate, ModifiedDate, active) values ('Defect 1', now(), now(), 1);
insert into defect (nativeId, createdDate, ModifiedDate, active) values ('Defect 2', now(), now(), 1);
insert into defect (nativeId, createdDate, ModifiedDate, active) values ('Defect 3', now(), now(), 1);

insert into Waf (name, createdDate, ModifiedDate, active) values ('Waf 1', now(), now(), 1);
insert into Waf (name, createdDate, ModifiedDate, active) values ('Waf 2', now(), now(), 1);
insert into Waf (name, createdDate, ModifiedDate, active) values ('Waf 3', now(), now(), 1);

insert into WafType(name) values ('WafType 1');
insert into WafType(name) values ('WafType 2');

INSERT INTO ChannelType (Name, Url, Version) VALUES ('Fortify 360', 'http://www.fortify.com', '2.5.0');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Microsoft CAT.NET', 'http://msdn.microsoft.com/en-us/security/default.aspx', '1 CTP');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Checkmarx CxSuite', 'http://www.checkmarx.com/index.aspx', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Find Bugs', 'http://findbugs.sourceforge.net/', '1.3.9');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('OWASP Orizon', 'http://www.owasp.org/index.php/Category:OWASP_Orizon_Project', '1.19');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan Source Edition', 'http://www-01.ibm.com/software/rational/products/appscan/source/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('IBM Rational AppScan', 'http://www-01.ibm.com/software/awdtools/appscan/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('Mavituna Security Netsparker', 'http://www.mavitunasecurity.com/', '-');
INSERT INTO ChannelType (Name, Url, Version) VALUES ('WhiteHat Sentinel', 'http://www.whitehatsec.com/home/services/services.html', '-');

insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (1, 1, now(), now(), 1);
insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (2, 2, now(), now(), 1);
insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (3, 3, now(), now(), 1);
insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (1, 4, now(), now(), 1);
insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (2, 5, now(), now(), 1);
insert into ApplicationChannel(applicationId, channelTypeId, createdDate, ModifiedDate, active) VALUES (3, 6, now(), now(), 1);

insert into scan (applicationChannelId, applicationId) values (1, 1);
insert into scan (applicationChannelId, applicationId) values (2, 1);
insert into scan (applicationChannelId, applicationId) values (1, 3);
insert into scan (applicationChannelId, applicationId) values (2, 3);

insert into GenericVulnerability(name) values ('Generic Vulnerability 1');
insert into GenericVulnerability(name) values ('Generic Vulnerability 2');
insert into GenericVulnerability(name) values ('Generic Vulnerability 3');

insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash1', 'VarHash1', 1, 1, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash2', 'VarHash2', 2, 2, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash3', 'VarHash3', 3, 1, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericvulnerabilityId, active, expired) values('LocHash4', 'VarHash4', 4, 2, true, false);
-- Same Hash Test
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash5', 'VarHash5', 2, 2, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash5', 'VarHash6', 2, 2, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash7', 'VarHash7', 2, 2, true, false);
insert into vulnerability(locationHash, variableHash, applicationId, genericVulnerabilityId, active, expired) values('LocHash8', 'VarHash7', 2, 2, true, false);
-- Hash Testing in ScanServiceImpl
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (2, null, 'locationVariableHash1', null, false, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (2, 'locationHash2', null, null, false, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (2, null, null, 'variableHash3', false, false);
-- Inactive Vulns
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (1, 'locationHash12', 'locationVariableHash12', 'variableHash12', false, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (1, 'locationHash13', 'locationVariableHash13', 'variableHash13', false, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (1, 'locationHash14', 'locationVariableHash14', 'variableHash14', false, false);
-- Active Vulns for App 1 & 2 (App 1 = +1 Above // App 2 = + 5 Above)
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (1, 'locationHash15', 'locationVariableHash15', 'variableHash15', true, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (1, 'locationHash16', 'locationVariableHash16', 'variableHash16', true, false);
insert into vulnerability(applicationId, locationHash, locationVariableHash, variableHash, active, expired) values (2, 'locationHash17', 'locationVariableHash17', 'variableHash17', true, false);


insert into Finding(nativeId) values ('Native Id 1');
insert into Finding(nativeId) values ('Native Id 2');
insert into Finding(nativeId) values ('Native Id 3');

insert into WafRule (rule, vulnerabilityid, wafid) values ('WafRule 1', 1, 1);
insert into WafRule (rule, vulnerabilityid, wafid) values ('WafRule 2', 2, 2);
insert into WafRule (rule, vulnerabilityid, wafid) values ('WafRule 3', 3, 3);

INSERT INTO Role (id, displayName, name) VALUES (1, 'Administrator', 'ROLE_ADMIN');
INSERT INTO Role (id, displayName, name) VALUES (2, 'User', 'ROLE_USER');

INSERT INTO User (id, name, password, salt, roleId, createdDate, ModifiedDate, failedpasswordattemptwindowstart, failedpasswordattempts, lastlogindate, lastpasswordchangeddate, active, approved, locked) VALUES (1, 'Bob', 'BobPass', 'BobSalt', 1, now(), now(), now(), 0, now(), now(), 1, 1, 0);
INSERT INTO User (id, name, password, salt, roleId, createdDate, ModifiedDate, failedpasswordattemptwindowstart, failedpasswordattempts, lastlogindate, lastpasswordchangeddate, active, approved, locked) VALUES (2, 'Carl', 'CarlPass', 'CarlSalt', 2, now(), now(), now(), 0, now(), now(), 1, 1, 0);
INSERT INTO User (id, name, password, salt, roleId, createdDate, ModifiedDate, failedpasswordattemptwindowstart, failedpasswordattempts, lastlogindate, lastpasswordchangeddate, active, approved, locked) VALUES (3, 'Sam', 'SamPass', 'SamSalt', 2, now(), now(), now(), 0, now(), now(), 1, 1, 0);

INSERT INTO Survey (id, name, createdDate, modifiedDate, active) VALUES (1, 'OpenSAMM Maturity Survey', now(), now(), 1);
INSERT INTO Survey (id, name, createdDate, modifiedDate, active) VALUES (2, '"Joel Test" Survey', now(), now(), 1);