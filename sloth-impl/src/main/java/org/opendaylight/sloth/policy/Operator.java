/*
 * Copyright © 2016 Northwestern University LIST Lab, Libin Song and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.sloth.policy;


import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public enum Operator {
    LT(0, "<"), GT(1, ">"), LE(2, "<="), GE(3, ">="), AND(4, "&&"), OR(5, "||"), EQ(6, "=="),
    NEQ(7, "!="), REG(8, "REG");
    private static final Map<Integer, Operator> VALUE_MAP;

    static {
        VALUE_MAP = new HashMap<>();
        for (Operator result : Operator.values()) {
            VALUE_MAP.put(result.getIntValue(), result);
        }
    }

    private int value;
    private String name;

    Operator(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public static Operator forValue(int value) {
        return VALUE_MAP.get(value);
    }

    public static Operator parse(String name) {
        for (Operator v : VALUE_MAP.values()) {
            if (Objects.equals(v.getName(), name)) {
                return v;
            }
        }
        throw new IllegalArgumentException();
    }

    public String getName() {
        return name;
    }

    public int getIntValue() {
        return value;
    }
}
