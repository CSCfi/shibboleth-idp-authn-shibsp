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
import java.util.function.Predicate;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.logic.Constraint;

/**
 * An abstract class for {@link Predicate}s dealing with {@link ShibbolethSpAuthenticationContext}.
 */
public abstract class AbstractShibbolethSpContextPredicate implements Predicate<ProfileRequestContext> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractShibbolethSpContextPredicate.class);

    /**
     * Strategy used to extract, and create if necessary, the {@link AuthenticationContext} from the
     * {@link ProfileRequestContext}.
     */
    @Nonnull private Function<ProfileRequestContext,AuthenticationContext> authnCtxLookupStrategy;

    /**
     * Constructor.
     */
    public AbstractShibbolethSpContextPredicate() {
        authnCtxLookupStrategy = new ChildContextLookup<>(AuthenticationContext.class);
    }
    
    /**
     * Set the context lookup strategy.
     * 
     * @param strategy  lookup strategy function for {@link AuthenticationContext}.
     */
    public void setAuthenticationContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,AuthenticationContext> strategy) {
        authnCtxLookupStrategy = Constraint.isNotNull(strategy, "Strategy cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    public boolean test(ProfileRequestContext profileRequestContext) {
        final AuthenticationContext authnContext = authnCtxLookupStrategy.apply(profileRequestContext);
        if (authnContext == null) {
            log.error("No authentication context found, nothing to do");
            return false;
        }
        final ShibbolethSpAuthenticationContext shibbolethContext
            = authnContext.getSubcontext(ShibbolethSpAuthenticationContext.class);
        if (shibbolethContext == null) {
            log.error("No shibboleth SP authentication context found, nothing to do");
            return false;
        }
        return doTest(shibbolethContext);
    }
    
    /**
     * Evaluates this predicate on the given {@link ShibbolethSpAuthenticationContext}.
     * 
     * @param shibbolethContext the input argument.
     * @return {@code true} if the input argument matches the predicate,
     * otherwise {@code false}
     */
    protected abstract boolean doTest(final ShibbolethSpAuthenticationContext shibbolethContext);

}
