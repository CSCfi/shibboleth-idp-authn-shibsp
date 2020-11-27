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

package fi.mpass.shibboleth.authn.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Configures the {@link ShibbolethSpAuthnServlet}.
 */
public class ServletContainerConfiguration implements ServletContainerInitializer {

    public static final String PROPERTY_KEY_MAPPINGS = "ShibbolethSpAuthnServlet";
    
    public static final String DEFAULT_SERVLET_MAPPING = "/Authn/ShibExternal";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ServletContainerConfiguration.class);
    
    @Override
    public void onStartup(Set<Class<?>> c, ServletContext servletContext) throws ServletException {
        
        final String idpHome = System.getProperty("idp.home") == null ? 
                "/opt/shibboleth-idp" : System.getProperty("idp.home");
        
        final String propertiesFile = System.getProperty("idp.authn.shibsp.external.mappings",
                idpHome + "/conf/authn/shibsp-external.properties");
        log.info("The properties file configured to: {}", propertiesFile);
        
        int counter = 0;
        for (final String mapping : loadMappings(propertiesFile)) {
            ServletRegistration.Dynamic registration = servletContext.addServlet(PROPERTY_KEY_MAPPINGS + counter,
                    new ShibbolethSpAuthnServlet());
            registration.addMapping(mapping.trim());
            log.info("Added a mapping {} for the external servlet", mapping.trim());
            counter = counter + 1;
        }
    }
    
    protected String[] loadMappings(final String propertiesFile) {
        final Properties properties = new Properties();
        try {
            final InputStream stream = new FileInputStream(propertiesFile);
            properties.load(stream);
        } catch (final IOException e) {
            log.info("Could not load properties from {}, using default mapping", propertiesFile);
            return new String[] { DEFAULT_SERVLET_MAPPING };
        }
        final String mappings = (String) properties.get(PROPERTY_KEY_MAPPINGS);
        if (StringSupport.trimOrNull(mappings) != null) {
            log.info("Returning mappings from the properties file {}", propertiesFile);
            return mappings.split(",");
        }
        log.info("Could not load mappings from the properties file {}, using default mapping", propertiesFile);
        return new String[] { DEFAULT_SERVLET_MAPPING };
    }

}
