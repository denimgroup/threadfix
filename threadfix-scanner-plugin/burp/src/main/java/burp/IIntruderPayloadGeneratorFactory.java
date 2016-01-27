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
 * @(#)IIntruderPayloadGeneratorFactory.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerIntruderPayloadGeneratorFactory()</code>
 * to register a factory for custom Intruder payloads.
 */
public interface IIntruderPayloadGeneratorFactory
{
    /**
     * This method is used by Burp to obtain the name of the payload generator.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use extension-generated payloads.
     *
     * @return The name of the payload generator.
     */
    String getGeneratorName();

    /**
     * This method is used by Burp when the user starts an Intruder attack that
     * uses this payload generator.
     *
     * @param attack An
     * <code>IIntruderAttack</code> object that can be queried to obtain details
     * about the attack in which the payload generator will be used.
     * @return A new instance of
     * <code>IIntruderPayloadGenerator</code> that will be used to generate
     * payloads for the attack.
     */
    IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack);
}
