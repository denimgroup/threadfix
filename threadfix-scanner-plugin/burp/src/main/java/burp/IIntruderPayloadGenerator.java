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
 * @(#)IIntruderPayloadGenerator.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used for custom Intruder payload generators. Extensions
 * that have registered an
 * <code>IIntruderPayloadGeneratorFactory</code> must return a new instance of
 * this interface when required as part of a new Intruder attack.
 */
public interface IIntruderPayloadGenerator
{
    /**
     * This method is used by Burp to determine whether the payload generator is
     * able to provide any further payloads.
     *
     * @return Extensions should return
     * <code>false</code> when all the available payloads have been used up,
     * otherwise
     * <code>true</code>.
     */
    boolean hasMorePayloads();

    /**
     * This method is used by Burp to obtain the value of the next payload.
     *
     * @param baseValue The base value of the current payload position. This
     * value may be
     * <code>null</code> if the concept of a base value is not applicable (e.g.
     * in a battering ram attack).
     * @return The next payload to use in the attack.
     */
    byte[] getNextPayload(byte[] baseValue);

    /**
     * This method is used by Burp to reset the state of the payload generator
     * so that the next call to
     * <code>getNextPayload()</code> returns the first payload again. This
     * method will be invoked when an attack uses the same payload generator for
     * more than one payload position, for example in a sniper attack.
     */
    void reset();
}
