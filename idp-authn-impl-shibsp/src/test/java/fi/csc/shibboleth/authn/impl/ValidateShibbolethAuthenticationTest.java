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

import javax.security.auth.Subject;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicates;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import fi.csc.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.csc.shibboleth.authn.principal.impl.ShibHeaderPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.testing.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

/**
 * Unit tests for {@link ValidateShibbolethAuthentication}.
 */
public class ValidateShibbolethAuthenticationTest extends BaseAuthenticationContextTest {
    
    /** The action to be tested. */
    private ValidateShibbolethAuthentication action;
    
    /** The configuration for the attribute containing username. */
    private String uidConfig;
    
    /** The attribute containing username. */
    private String uid;
    
    /** The value of the username. */
    private String uidValue;
    
    /** {@inheritDoc} 
     * @throws ComponentInitializationException */
    @BeforeMethod public void setUp() throws ComponentInitializationException  {
        super.setUp();
        uidConfig = "username,username2";
        uid = "username";
        uidValue = "mockUser";
        action = new ValidateShibbolethAuthentication();
        action.setUsernameAttribute(uidConfig);
        Assert.assertEquals(action.getUsernameAttribute(), uidConfig);
        action.setPopulateAttributes(true);
        action.setPopulateHeaders(true);
        action.setPopulateIdpAttributes(true);
        action.initialize();
    }

    /**
     * Runs action without attempted flow.
     */
    @Test public void testMissingFlow() {
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_AUTHN_CTX);
    }
    
    /**
     * Runs action without {@link ShibbolethSpAuthenticationContext}.
     */
    @Test public void testMissingContext() {
        prc.getSubcontext(AuthenticationContext.class).setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_AUTHN_CTX);
    }

    /**
     * Runs action without username attribute.
     */
    @Test public void testMissingUser() {
        prc.getSubcontext(AuthenticationContext.class).setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethSpAuthenticationContext shibContext = prc.getSubcontext(AuthenticationContext.class)
                .ensureSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibContext);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }
    
    /**
     * Runs action with authentication acceptable predicate set to always return false.
     */
    @Test public void testFailingAcceptablePredicate() throws Exception{
        action = new ValidateShibbolethAuthentication();
        action.setUsernameAttribute(uid);
        action.setPopulateAttributes(true);
        action.setPopulateHeaders(true);
        action.setAuthenticationAcceptablePredicate(Predicates.alwaysFalse());
        action.initialize();
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethSpAuthenticationContext shibContext = prc.getSubcontext(AuthenticationContext.class)
                .ensureSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibContext);
        shibContext.getAttributes().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_CREDENTIALS);        
    }
    
    /**
     * Runs action with username in attribute map with.
     * @param action Already initialized {@link ValidateShibbolethAuthentication} action.
     */
    public void testAttribute(final ValidateShibbolethAuthentication action) {
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethSpAuthenticationContext shibContext = prc.getSubcontext(AuthenticationContext.class)
                .ensureSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibContext);
        shibContext.getAttributes().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ac.getAuthenticationResult());
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
        Assert.assertEquals(subject.getPrincipals(ShibHeaderPrincipal.class).iterator().hasNext(), false);
        final ShibAttributePrincipal principal = subject.getPrincipals(ShibAttributePrincipal.class).iterator().next();
        Assert.assertEquals(principal.getValue(), uidValue);
    }

    /**
     * Runs action with username in attribute map with.
     * @param action Already initialized {@link ValidateShibbolethAuthentication} action.
     */
    public void testIdpAttribute(final ValidateShibbolethAuthentication action) {
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethSpAuthenticationContext shibContext = prc.getSubcontext(AuthenticationContext.class)
                .ensureSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibContext);
        shibContext.getHeaders().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ac.getAuthenticationResult());
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
        Assert.assertEquals(subject.getPrincipals(ShibAttributePrincipal.class).iterator().hasNext(), false);
        final IdPAttributePrincipal principal = subject.getPrincipals(IdPAttributePrincipal.class).iterator().next();
        Assert.assertEquals(principal.getAttribute().getValues().get(0).getNativeValue().toString(), uidValue);
    }
    
    /**
     * Runs action with username in attribute map with multiple usernames in configuration.
     */
    @Test public void testAttribute() {
        testAttribute(action);
    }

    /**
     * Runs action with username in attribute map with single username in configuration.
     */
    @Test public void testAttributeSingle() throws Exception{
        action = new ValidateShibbolethAuthentication();
        action.setUsernameAttribute(uid);
        Assert.assertEquals(action.getUsernameAttribute(), uid);
        action.setPopulateAttributes(true);
        action.setPopulateHeaders(true);
        action.initialize();
        testAttribute(action);
    }

    /**
     * Runs action with username in attribute map with multiple usernames in configuration.
     */
    @Test public void testIdpAttribute() {
        testIdpAttribute(action);
    }
    
    /**
     * Runs action with username in attribute map with single username in configuration.
     */
    @Test public void testIdpAttributeSingle() throws Exception{
        action = new ValidateShibbolethAuthentication();
        action.setUsernameAttribute(uid);
        Assert.assertEquals(action.getUsernameAttribute(), uid);
        action.setPopulateAttributes(true);
        action.setPopulateHeaders(true);
        action.setPopulateIdpAttributes(true);
        action.initialize();
        testIdpAttribute(action);
    }

    /**
     * Runs action with username in HTTP headers map.
     */
    @Test public void testHeader() {
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethSpAuthenticationContext shibContext = prc.getSubcontext(AuthenticationContext.class)
                .ensureSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibContext);
        shibContext.getHeaders().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ac.getAuthenticationResult());
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
        Assert.assertEquals(subject.getPrincipals(ShibAttributePrincipal.class).iterator().hasNext(), false);
        final ShibHeaderPrincipal principal = subject.getPrincipals(ShibHeaderPrincipal.class).iterator().next();
        Assert.assertEquals(principal.getValue(), uidValue);
    }
    
    /**
     * Runs {@link ExtractShibbolethAttributesFromRequest) and {@link ValidateShibbolethAuthentication} together
     * and verify the authenticated user.
     * 
     * @throws ComponentInitializationException
     */
    @Test public void testCombinedUsernameResolution() throws ComponentInitializationException {
        final String prefix = "AJP_";
        final ExtractShibbolethAttributesFromRequest action1 = new ExtractShibbolethAttributesFromRequest(prefix);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action1.setHttpServletRequestSupplier(new NonnullSupplier<HttpServletRequest>() {

            @Override
            public MockHttpServletRequest get() {
                return httpRequest;
            }
            
        });
        ((MockHttpServletRequest) action1.getHttpServletRequest()).addHeader(prefix + uid, uidValue);
        action1.initialize();
        final Event event = action1.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final Event event2 = action.execute(src);
        Assert.assertNull(event2);
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
    }
}