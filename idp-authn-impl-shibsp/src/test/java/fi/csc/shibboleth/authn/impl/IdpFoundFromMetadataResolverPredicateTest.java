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

import java.util.Arrays;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.testng.Assert;
import org.testng.annotations.Test;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Unit tests for {@link IdpFoundFromMetadataResolverPredicate}.
 */
public class IdpFoundFromMetadataResolverPredicateTest
    extends BaseShibbolethSpContextPredicateTest<IdpFoundFromMetadataResolverPredicate> {

    static {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            e.printStackTrace();
        }
    }
    
    @Override
    protected IdpFoundFromMetadataResolverPredicate constructPredicate() {
        return new IdpFoundFromMetadataResolverPredicate(new SimpleResolver(expected));
    }
    
    @Test
    public void test_whenResolverThrowsException_shouldReturnFalse() {
        ThrowingResolver resolver = new ThrowingResolver(expected);
        predicate = new IdpFoundFromMetadataResolverPredicate(resolver);
        ShibbolethSpAuthenticationContext context = new ShibbolethSpAuthenticationContext();
        context.setIdp(expected);
        addShibbolethSpAuthenticationContext(context);
        Assert.assertFalse(predicate.test(prc));
    }

    protected class SimpleResolver extends AbstractMetadataResolver {
        
        final EntityDescriptor entityDescriptor;
        
        public SimpleResolver(final String entityID) {
            super();
            setId("mockId");
            entityDescriptor = new EntityDescriptorBuilder().buildObject();
            entityDescriptor.setEntityID(entityID);
            try {
                initialize();
            } catch (ComponentInitializationException e) {
                e.printStackTrace();
            }
        }

        @Override
        public Iterable<EntityDescriptor> resolve(CriteriaSet criteria) throws ResolverException {
            return Arrays.asList(entityDescriptor);
        }
    }
    
    protected class ThrowingResolver extends SimpleResolver {

        public ThrowingResolver(String entityID) {
            super(entityID);
        }

        @Override
        public Iterable<EntityDescriptor> resolve(CriteriaSet criteria) throws ResolverException {
            throw new ResolverException("obsolete");
        }

    }
}
