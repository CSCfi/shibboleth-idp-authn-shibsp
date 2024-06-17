/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fi.csc.shibboleth.authn.impl;

import java.util.List;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * A predicate to check if the current identity provider was found from the list of expected IdPs.
 */
public class IdpFoundFromExpectedListPredicate extends AbstractShibbolethSpContextPredicate {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(IdpFoundFromExpectedListPredicate.class);

    /** The expected/accepted values for the identity provider. */
    private final List<String> expectedIdps;
    
    /**
     * Constructor.
     *
     * @param expected The expected/accepted values for the identity provider.
     */
    public IdpFoundFromExpectedListPredicate(@Nonnull final List<String> expected) {
        expectedIdps = Constraint.isNotNull(expected, "The expected string cannot be empty");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doTest(ShibbolethSpAuthenticationContext shibbolethContext) {
        final String idp = shibbolethContext.getIdp();
        if (StringSupport.trimOrNull(idp) == null) {
            log.error("No identity provider set in the ShibbolethSpAuthenticationContext");
            return false;
        }
        if (expectedIdps.contains(idp)) {
            log.debug("The identity provider {} matches the expected value", idp);
            return true;
        }
        log.warn("The current identity provider {} not included in the list of expected IdPs {}", idp, expectedIdps);
        return false;
    }

}
