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

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.idp.authn.impl.testing.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

import java.util.Arrays;
import java.util.Map;

import javax.security.auth.Subject;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import fi.csc.shibboleth.authn.principal.impl.ShibHeaderPrincipal;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for {@link ExtractShibbolethAttributesFromRequest}.
 */
public class ExtractShibbolethAttributesFromRequestTest extends BaseAuthenticationContextTest {

    /** The action to be tested. */
    private ExtractShibbolethAttributesFromRequest action;

    /** The idp of the context. */
    private String expectedIdp;

    /** The instant of the context. */
    private String expectedInstant;

    /** The contextClass of the context. */
    private String expectedContextClass;

    /** The contextDecl of the context. */
    private String expectedContextDecl;
    
    /** The method of the context. */
    private String expectedMethod;
    
    /** The request attribute. */
    private String expectedAttribute;
    
    /** The HTTP header. */
    private String expectedHeader;
    
    /** {@inheritDoc} 
     * @throws ComponentInitializationException */
    @BeforeMethod
    public void setUp() throws ComponentInitializationException  {
        super.setUp();
    }

    /**
     * Initializes the expected context variables.
     */
    @BeforeTest
    public void initTest() {
        expectedIdp = "mockIdp";
        expectedInstant = "mockInstant";
        expectedContextClass = "mockContextClass";
        expectedContextDecl = "mockContextDecl";
        expectedMethod = "mockMethod";
        expectedAttribute = "mockAttribute";
        expectedHeader = "mockHeader";
    }

    /**
     * Tests action without {@link HttpServletRequest}.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testNoServlet() throws ComponentInitializationException {
        action = new ExtractShibbolethAttributesFromRequest();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext} with prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithPrefixNoAttributes() throws ComponentInitializationException {
        testSuccessNoAttributes("AJP_");
    }
    
    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext} without prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithoutPrefixNoAttributes() throws ComponentInitializationException {
        testSuccessNoAttributes("");
    }

    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext} with prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithPrefixWithAttributes() throws ComponentInitializationException {
        testSuccessWithAttributes("AJP_");
    }
    
    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext} without prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithoutPrefixWithAttributes() throws ComponentInitializationException {
        testSuccessWithAttributes("");
    }

    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext}.
     * 
     * @param prefix The prefix for the headers.
     * @throws ComponentInitializationException 
     */
    public void testSuccessNoAttributes(final String prefix) throws ComponentInitializationException {
        action = new ExtractShibbolethAttributesFromRequest(prefix);
        final ShibbolethSpAuthenticationContext shibCtx = testSuccess(action, prefix, 0);
        Assert.assertEquals(shibCtx.getAttributes().get(expectedAttribute), null);
    }

    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext}.
     * 
     * @param prefix The prefix for the headers.
     * @throws ComponentInitializationException 
     */
    public void testSuccessWithAttributes(final String prefix) throws ComponentInitializationException {
        action = new ExtractShibbolethAttributesFromRequest(prefix);
        action.setAttributeNames(Arrays.asList(expectedAttribute));
        final ShibbolethSpAuthenticationContext shibCtx = testSuccess(action, prefix, 1);
        Assert.assertEquals(shibCtx.getAttributes().get(expectedAttribute), expectedAttribute);
    }

    protected ShibbolethSpAuthenticationContext testSuccess(ExtractShibbolethAttributesFromRequest action, String prefix,
            int expectedAttributes) throws ComponentInitializationException {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<HttpServletRequest>() {

            @Override
            public MockHttpServletRequest get() {
                return httpRequest;
            }
            
        });
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethSpAuthenticationContext.SHIB_SP_AUTHENTICATION_INSTANT, expectedInstant);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethSpAuthenticationContext.SHIB_SP_AUTHENTICATION_METHOD, expectedMethod);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethSpAuthenticationContext.SHIB_SP_AUTHN_CONTEXT_CLASS, expectedContextClass);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix  + ShibbolethSpAuthenticationContext.SHIB_SP_AUTHN_CONTEXT_DECL, expectedContextDecl);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethSpAuthenticationContext.SHIB_SP_IDENTITY_PROVIDER, expectedIdp);
        ((MockHttpServletRequest) action.getHttpServletRequest()).addHeader(expectedHeader, expectedHeader);
        ((MockHttpServletRequest) action.getHttpServletRequest()).setAttribute(expectedAttribute, expectedAttribute);
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final ShibbolethSpAuthenticationContext shibCtx = authCtx.getSubcontext(ShibbolethSpAuthenticationContext.class);
        Assert.assertNotNull(shibCtx, "No shibboleth context attached");
        Assert.assertEquals(shibCtx.getIdp(), expectedIdp);
        Assert.assertEquals(shibCtx.getInstant(), expectedInstant);
        Assert.assertEquals(shibCtx.getMethod(), expectedMethod);
        Assert.assertEquals(shibCtx.getContextClass(), expectedContextClass);
        Assert.assertEquals(shibCtx.getContextDecl(), expectedContextDecl);
        Assert.assertEquals(shibCtx.getAttributes().size(), expectedAttributes);
        Assert.assertEquals(shibCtx.getHeaders().size(), 6);
        Assert.assertEquals(shibCtx.getHeaders().get(expectedHeader), expectedHeader);
        return shibCtx;
    }
    
    /**
     * Tests external authentication method without {@link ExternalAuthenticationContext}.
     * @throws ComponentInitializationException
     */
    @Test
    public void testExternalNoContext() throws ComponentInitializationException {
        action = initAction(true);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests external authentication method without subject in {@link ExternalAuthenticationContext}.
     * @throws ComponentInitializationException
     */
    @Test
    public void testExternalNoSubject() throws ComponentInitializationException {
        action = initAction(true);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        authCtx.addSubcontext(new ExternalAuthenticationContext(new ExternalAuthenticationImpl(false)));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests external authentication method with empty subject in {@link ExternalAuthenticationContext}.
     * @throws ComponentInitializationException
     */
    @Test
    public void testExternalEmptySubject() throws ComponentInitializationException {
        action = initAction(true);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final ExternalAuthenticationContext extCtx = new ExternalAuthenticationContext(new ExternalAuthenticationImpl(false));
        extCtx.setSubject(new Subject());
        authCtx.addSubcontext(extCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        Assert.assertEquals(authCtx.getSubcontext(ShibbolethSpAuthenticationContext.class).getHeaders().size(), 0);
    }
    
    /**
     * Tests successful construction of {@link ShibbolethSpAuthenticationContext} with external authentication method.
     * @throws ComponentInitializationException
     */
    @Test
    public void testExternalSuccess() throws ComponentInitializationException {
        action = initAction(true);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        final ExternalAuthenticationContext extCtx = new ExternalAuthenticationContext(new ExternalAuthenticationImpl(false));
        final String headerName = "mockName";
        final String headerValue = "mockValue";
        final Subject subject = new Subject();
        subject.getPrincipals().add(new ShibHeaderPrincipal(headerName, headerValue));
        extCtx.setSubject(subject);
        authCtx.addSubcontext(extCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final Map<String, String> headers = authCtx.getSubcontext(ShibbolethSpAuthenticationContext.class).getHeaders();
        Assert.assertEquals(headers.size(), 1);
        Assert.assertEquals(headers.get(headerName), headerValue);
    }
    
    /**
     * Initializes the action.
     * @param exploitExternal
     * @return
     * @throws ComponentInitializationException
     */
    protected ExtractShibbolethAttributesFromRequest initAction(boolean exploitExternal) throws ComponentInitializationException {
        ExtractShibbolethAttributesFromRequest action = new ExtractShibbolethAttributesFromRequest();
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<HttpServletRequest>() {

            @Override
            public MockHttpServletRequest get() {
                return httpRequest;
            }
            
        });
        action.setExploitExternal(true);
        action.initialize();
        return action;
    }
}
