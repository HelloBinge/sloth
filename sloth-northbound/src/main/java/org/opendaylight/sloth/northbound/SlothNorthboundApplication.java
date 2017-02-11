/*
 * Copyright © 2016 Northwestern University LIST Lab, Libin Song and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.sloth.northbound;

import org.eclipse.persistence.jaxb.rs.MOXyJsonProvider;

import javax.ws.rs.core.Application;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SlothNorthboundApplication extends Application {
    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> set = new HashSet<>();
        set.add(SlothNorthboundImpl.class);
        return set;
    }

    @Override
    public Set<Object> getSingletons() {
        MOXyJsonProvider moxyJsonProvider = new MOXyJsonProvider();
        moxyJsonProvider.setAttributePrefix("@");
        moxyJsonProvider.setFormattedOutput(true);
        moxyJsonProvider.setIncludeRoot(false);
        moxyJsonProvider.setMarshalEmptyCollections(true);
        moxyJsonProvider.setValueWrapper("$");

        Map<String, String> namespacePrefixMapper = new HashMap<String, String>();
        // FIXME: fill in next two with XSD
        namespacePrefixMapper.put("router", "router");
        namespacePrefixMapper.put("provider", "provider");
        namespacePrefixMapper.put("binding", "binding");
        moxyJsonProvider.setNamespacePrefixMapper(namespacePrefixMapper);
        moxyJsonProvider.setNamespaceSeparator(':');

        Set<Object> set = new HashSet<Object>();
        set.add(moxyJsonProvider);
        return set;
    }
}
