////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

/**
 * Created by sgerick on 10/28/2014.
 */
public class CppcheckScanTest {
    //cwe name, severity, path, parameter
    private final static String[][] cppcheckResults = new String [][] {
		    {"Assignment to Variable without Use ('Unused Variable')","Medium","c:\\TrinitySource\\dep\\CascLib\\src\\CascBuildCfg.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')","High","c:\\TrinitySource\\dep\\CascLib\\src\\CascDumpData.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascFindFile.cpp",""},
		    {"Improper Fulfillment of API Contract ('API Abuse')","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"Assignment to Variable without Use ('Unused Variable')","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"Assignment to Variable without Use ('Unused Variable')","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"Assignment to Variable without Use ('Unused Variable')","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"Improper Release of Memory Before Removing Last Reference ('Memory Leak')","High","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"Indicator of Poor Code Quality","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascMndxRoot.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\dep\\CascLib\\src\\CascOpenFile.cpp",""},
		    {"Missing Initialization of a Variable","Medium","c:\\TrinitySource\\src\\server\\scripts\\EasternKingdoms\\ZulGurub\\boss_mandokir.cpp",""},
		    {"CERT C++ Secure Coding Section 03 - Expressions (EXP)","Low","c:\\TrinitySource\\src\\server\\scripts\\Spells\\spell_mage.cpp",""},
		    {"Improper Fulfillment of API Contract ('API Abuse')","Low","c:\\TrinitySource\\src\\server\\shared\\Logging\\Log.cpp",""},
		    {"Use of Uninitialized Variable","Medium","c:\\TrinitySource\\src\\tools\\mesh_extractor\\MPQ.h",""},
		    {"Assignment to Variable without Use ('Unused Variable')","Low","c:\\TrinitySource\\src\\tools\\mesh_extractor\\MeshExtractor.cpp",""},
		    {"CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)","Low","c:\\TrinitySource\\src\\tools\\mmaps_generator\\PathCommon.h",""},
		    {"Dead Code","Low","c:\\TrinitySource\\dep\\zmqpp\\zmqpp\\zmqpp.cpp",""},
		    {"Assignment to Variable without Use ('Unused Variable')","Medium","c:\\TrinitySource\\dep\\CascLib\\src\\CascBuildCfg.cpp",""}
    };

	@Test
	public void cppcheckScanTest() {
		ScanComparisonUtils.compare(cppcheckResults, ScanLocationManager.getRoot() +
				"Static/Cppcheck/cppcheckScanTest.xml");
	}
}
