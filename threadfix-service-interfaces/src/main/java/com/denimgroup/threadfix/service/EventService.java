////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Event;

import java.util.List;

public interface EventService {
	
	String VALID = "Valid Comment.", LENGTH = "The comment was too long.",
			EMPTY = "The comment cannot be empty.", VULN = "The submitted vuln was invalid.",
			USER = "The session's user was invalid. Please let the ThreadFix team know about this.";

	String createEvent();

    void saveEvent(Event vulnerabilityComment);

	Event loadEventById(int eventId);

}
