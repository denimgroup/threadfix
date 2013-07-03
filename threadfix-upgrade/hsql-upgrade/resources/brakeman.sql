INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Authentication', 'Authentication', (SELECT id FROM ChannelType WHERE name = 'Brakeman'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Denial of Service', 'Denial of Service', (SELECT id FROM ChannelType WHERE name = 'Brakeman'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Remote Code Execution', 'Remote Code Execution', (SELECT id FROM ChannelType WHERE name = 'Brakeman'));

INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Brakeman') AND code = 'Authentication'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Authentication'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Brakeman') AND code = 'Denial of Service'), (SELECT id FROM GenericVulnerability WHERE name = 'Uncontrolled Resource Consumption (''Resource Exhaustion'')'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = (SELECT id FROM ChannelType WHERE name = 'Brakeman') AND code = 'Remote Code Execution'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Control of Generation of Code (''Code Injection'')'));

-- Update column size
ALTER TABLE GenericVulnerability MODIFY name VARCHAR(256);

-- Add new generics
INSERT INTO GenericVulnerability (name, id) VALUES ('Use of Uninitialized Resource', '908');
INSERT INTO GenericVulnerability (name, id) VALUES ('Missing Initialization of Resource', '909');
INSERT INTO GenericVulnerability (name, id) VALUES ('Use of Expired File Descriptor', '910');
INSERT INTO GenericVulnerability (name, id) VALUES ('Improper Update of Reference Count', '911');
INSERT INTO GenericVulnerability (name, id) VALUES ('Hidden Functionality', '912');
INSERT INTO GenericVulnerability (name, id) VALUES ('Improper Control of Dynamically-Managed Code Resources', '913');
INSERT INTO GenericVulnerability (name, id) VALUES ('Improper Control of Dynamically-Identified Variables', '914');
INSERT INTO GenericVulnerability (name, id) VALUES ('Improperly Controlled Modification of Dynamically-Determined Object Attributes', '915');
INSERT INTO GenericVulnerability (name, id) VALUES ('Use of Password Hash With Insufficient Computational Effort', '916');
INSERT INTO GenericVulnerability (name, id) VALUES ('Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')', '917');
INSERT INTO GenericVulnerability (name, id) VALUES ('Server-Side Request Forgery (SSRF)', '918');

-- Add corresponding Channel Vulns
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Use of Uninitialized Resource', 'Use of Uninitialized Resource', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Missing Initialization of Resource', 'Missing Initialization of Resource', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Use of Expired File Descriptor', 'Use of Expired File Descriptor', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Improper Update of Reference Count', 'Improper Update of Reference Count', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Hidden Functionality', 'Hidden Functionality', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Improper Control of Dynamically-Managed Code Resources', 'Improper Control of Dynamically-Managed Code Resources', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Improper Control of Dynamically-Identified Variables', 'Improper Control of Dynamically-Identified Variables', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Improperly Controlled Modification of Dynamically-Determined Object Attributes', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Use of Password Hash With Insufficient Computational Effort', 'Use of Password Hash With Insufficient Computational Effort', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')', 'Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')', (SELECT id FROM ChannelType WHERE name = 'Manual'));
INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('Server-Side Request Forgery (SSRF)', 'Server-Side Request Forgery (SSRF)', (SELECT id FROM ChannelType WHERE name = 'Manual'));

-- Map em
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Use of Uninitialized Resource'), (SELECT id FROM GenericVulnerability WHERE name = 'Use of Uninitialized Resource'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Missing Initialization of Resource'), (SELECT id FROM GenericVulnerability WHERE name = 'Missing Initialization of Resource'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Use of Expired File Descriptor'), (SELECT id FROM GenericVulnerability WHERE name = 'Use of Expired File Descriptor'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Improper Update of Reference Count'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Update of Reference Count'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Hidden Functionality'), (SELECT id FROM GenericVulnerability WHERE name = 'Hidden Functionality'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Improper Control of Dynamically-Managed Code Resources'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Control of Dynamically-Managed Code Resources'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Improper Control of Dynamically-Identified Variables'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Control of Dynamically-Identified Variables'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'), (SELECT id FROM GenericVulnerability WHERE name = 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Use of Password Hash With Insufficient Computational Effort'), (SELECT id FROM GenericVulnerability WHERE name = 'Use of Password Hash With Insufficient Computational Effort'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')'), (SELECT id FROM GenericVulnerability WHERE name = 'Improper Neutralization of Special Elements used in an Expression Language Statement (''Expression Language Injection'')'));
INSERT INTO VulnerabilityMap (mappable, channelVulnerabilityId, genericVulnerabilityId) VALUES (1,(SELECT id FROM ChannelVulnerability WHERE channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual') AND code = 'Server-Side Request Forgery (SSRF)'), (SELECT id FROM GenericVulnerability WHERE name = 'Server-Side Request Forgery (SSRF)'));

-- Update Generic texts
UPDATE GenericVulnerability SET name='Information Exposure Through Self-generated Error Message' WHERE id='210';
UPDATE GenericVulnerability SET name='Information Exposure Through Externally-generated Error Message' WHERE id='211';
UPDATE GenericVulnerability SET name='Improper Certificate Validation' WHERE id='295';
UPDATE GenericVulnerability SET name='Improper Following of a Certificate''s Chain of Trust' WHERE id='296';
UPDATE GenericVulnerability SET name='Improper Validation of Certificate with Host Mismatch' WHERE id='297';
UPDATE GenericVulnerability SET name='Exposure of File Descriptor to Unintended Control Sphere (''File Descriptor Leak'')' WHERE id='403';
UPDATE GenericVulnerability SET name='Unintended Proxy or Intermediary (''Confused Deputy'')' WHERE id='441';
UPDATE GenericVulnerability SET name='Missing Initialization of a Variable' WHERE id='456';
UPDATE GenericVulnerability SET name='Missing Validation of OpenSSL Certificate' WHERE id='599';
UPDATE GenericVulnerability SET name='Improper Restriction of XML External Entity Reference (''XXE'')' WHERE id='611';
UPDATE GenericVulnerability SET name='Execution After Redirect (EAR)' WHERE id='698';
UPDATE GenericVulnerability SET name='Improper Restriction of Recursive Entity References in DTDs (''XML Entity Expansion'')' WHERE id='776';
UPDATE GenericVulnerability SET name='Improper Validation of Function Hook Arguments' WHERE id='622';

-- Update Manual Texts
UPDATE ChannelVulnerability SET name='Information Exposure Through Self-generated Error Message', code='Information Exposure Through Self-generated Error Message' WHERE code='Information Exposure Through Generated Error Message' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Information Exposure Through Externally-generated Error Message', code='Information Exposure Through Externally-generated Error Message' WHERE code='Information Exposure Through External Error Message' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Certificate Validation', code='Improper Certificate Validation' WHERE code='Certificate Issues' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Following of a Certificate''s Chain of Trust', code='Improper Following of a Certificate''s Chain of Trust' WHERE code='Improper Following of Chain of Trust for Certificate Validation' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Validation of Certificate with Host Mismatch', code='Improper Validation of Certificate with Host Mismatch' WHERE code='Improper Validation of Host-specific Certificate Data' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Exposure of File Descriptor to Unintended Control Sphere (''File Descriptor Leak'')', code='Exposure of File Descriptor to Unintended Control Sphere (''File Descriptor Leak'')' WHERE code='Exposure of File Descriptor to Unintended Control Sphere' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Unintended Proxy or Intermediary (''Confused Deputy'')', code='Unintended Proxy or Intermediary (''Confused Deputy'')' WHERE code='Unintended Proxy/Intermediary' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Missing Initialization of a Variable', code='Missing Initialization of a Variable' WHERE code='Missing Initialization' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Missing Validation of OpenSSL Certificate', code='Missing Validation of OpenSSL Certificate' WHERE code='Trust of OpenSSL Certificate Without Validation' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Restriction of XML External Entity Reference (''XXE'')', code='Improper Restriction of XML External Entity Reference (''XXE'')' WHERE code='Information Exposure Through XML External Entity Reference' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Execution After Redirect (EAR)', code='Execution After Redirect (EAR)' WHERE code='Redirect Without Exit' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Restriction of Recursive Entity References in DTDs (''XML Entity Expansion'')', code='Improper Restriction of Recursive Entity References in DTDs (''XML Entity Expansion'')' WHERE code='Unrestricted Recursive Entity References in DTDs (''XML Bomb'')' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
UPDATE ChannelVulnerability SET name='Improper Validation of Function Hook Arguments', code='Improper Validation of Function Hook Arguments' WHERE code='Unvalidated Function Hook Arguments' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Manual');
