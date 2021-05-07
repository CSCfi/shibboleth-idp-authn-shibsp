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

import javax.annotation.Nonnull;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A predicate to verify whether the IdP entity ID stored in the authentication context is found from the
 * configured metadata resolver.
 * 
 * <bean id="HakaIdPFeed" class="org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver"
 * c:backupFilePath="%{idp.home}/metadata/backingFiles/haka-metadata.xml"
 * c:metadataURL="https://haka.funet.fi/metadata/haka-metadata.xml" />
 */
public class IdpFoundFromMetadataResolverPredicate extends AbstractShibbolethSpContextPredicate {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(IdpFoundFromMetadataResolverPredicate.class);

    /** The metadata resolver to be used as the verification source. */
    private final MetadataResolver resolver;
    
    /**
     * Constructor.
     *
     * @param metadataResolver The metadata resolver to search IdP entity ID from.
     */
    public IdpFoundFromMetadataResolverPredicate(final MetadataResolver metadataResolver) {
        super();
        resolver = Constraint.isNotNull(metadataResolver, "The metadata source cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doTest(ShibbolethSpAuthenticationContext shibbolethContext) {
        final String idp = shibbolethContext.getIdp();
        if (StringSupport.trimOrNull(idp) == null) {
            log.error("No identity provider set in the ShibbolethSpAuthenticationContext");
            return false;
        }
        final CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion(idp));
        try {
            final EntityDescriptor descriptor = resolver.resolveSingle(criteria);
            if (descriptor != null && idp.equals(descriptor.getEntityID())) {
                log.debug("The identity provider {} was found from the metadata resolver", idp);
                return true;
            }
        } catch (ResolverException e) {
            log.warn("Could not resolve metadata for {}", idp, e);
        }
        log.warn("The identity provider {} was not found from the metadata resolver", idp);
        return false;
    }    
}