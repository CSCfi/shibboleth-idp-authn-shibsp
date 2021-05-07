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

import java.util.function.Function;

import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * Unit tests for predicates extending {@link AbstractShibbolethSpContextPredicate}.
 *
 * @param <P> A predicate extending {@link AbstractShibbolethSpContextPredicate}.
 */
public abstract class BaseShibbolethSpContextPredicateTest<P extends AbstractShibbolethSpContextPredicate> {

    protected P predicate;
    
    protected ProfileRequestContext prc;
    
    protected String expected = "https://idp.example.org/idp";
    
    protected abstract P constructPredicate();
    
    @BeforeMethod
    public void init() {
        prc = new ProfileRequestContext();
    }
    
    @Test
    public void testNoAuthnContext() {
        predicate = constructPredicate();
        predicate.setAuthenticationContextLookupStrategy(nullAuthenticationContext());
        Assert.assertFalse(predicate.test(null));
    }

    @Test
    public void testNoShibbolethSpAuthnContext() {
        predicate = constructPredicate();
        prc.addSubcontext(new AuthenticationContext());
        Assert.assertFalse(predicate.test(null));
    }

    @Test
    public void test_whenNoIdpSetInContext_shouldReturnFalse() {
        predicate = constructPredicate();
        addShibbolethSpAuthenticationContext(new ShibbolethSpAuthenticationContext());
        Assert.assertFalse(predicate.test(prc));
    }

    @Test
    public void test_whenExpectedIdpSetInContext_shouldReturnTrue() {
        predicate = constructPredicate();
        ShibbolethSpAuthenticationContext context = new ShibbolethSpAuthenticationContext();
        context.setIdp(expected);
        addShibbolethSpAuthenticationContext(context);
        Assert.assertTrue(predicate.test(prc));
    }

    @Test
    public void test_whenUnexpectedIdpSetInContext_shouldReturnTrue() {
        predicate = constructPredicate();
        ShibbolethSpAuthenticationContext context = new ShibbolethSpAuthenticationContext();
        context.setIdp(expected + "/not");
        addShibbolethSpAuthenticationContext(context);
        Assert.assertFalse(predicate.test(prc));
    }

    protected Function<ProfileRequestContext, AuthenticationContext> nullAuthenticationContext() {
        return new Function<ProfileRequestContext, AuthenticationContext>() {
            @Override
            public AuthenticationContext apply(ProfileRequestContext t) {
                return null;
            }
        };
    }

    protected void addShibbolethSpAuthenticationContext(ShibbolethSpAuthenticationContext context) {
        prc.getSubcontext(AuthenticationContext.class, true).addSubcontext(context);
    }
}
