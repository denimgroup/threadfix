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

package burp;

/*
 * @(#)IIntruderPayloadProcessor.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerIntruderPayloadProcessor()</code> to
 * register a custom Intruder payload processor.
 */
public interface IIntruderPayloadProcessor
{
    /**
     * This method is used by Burp to obtain the name of the payload processor.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use an extension-provided payload processor.
     *
     * @return The name of the payload processor.
     */
    String getProcessorName();

    /**
     * This method is invoked by Burp each time the processor should be applied
     * to an Intruder payload.
     *
     * @param currentPayload The value of the payload to be processed.
     * @param originalPayload The value of the original payload prior to
     * processing by any already-applied processing rules.
     * @param baseValue The base value of the payload position, which will be
     * replaced with the current payload.
     * @return The value of the processed payload. This may be
     * <code>null</code> to indicate that the current payload should be skipped,
     * and the attack will move directly to the next payload.
     */
    byte[] processPayload(
            byte[] currentPayload,
            byte[] originalPayload,
            byte[] baseValue);
}
