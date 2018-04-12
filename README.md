# Sloth Security Filter

![Sloth](http://kids.nationalgeographic.com/content/dam/kids/photos/animals/Mammals/Q-Z/sloth-beach-upside-down.jpg.adapt.945.1.jpg)

Author: Libin Song, Northwestern University

`Sloth Security Filter` is a light weight Java Servlet Filter with backend data store support, designed for OpenDaylight controller. It provides fine grained role based access control on generic RESTful API services. It also support runtime configuration and can be deployed distributedly. And it is easy to install and 100% compatible with existing AAA project. You don't need to change any things on existing OpenDaylight projects.

## Installation

1. Add `Sloth` as a CustomFilter
	* [Dynamic Filter Injection](https://wiki.opendaylight.org/view/AAA:DynamicFilterFramework)
2. Start `Sloth` feature in Karaf command line

## Feature

`Sloth` is a [Java Servlet Filter](https://docs.oracle.com/cd/B14099_19/web.1012/b14017/filters.htm). A Servlet Filter is able to filter before and after API is processed. `Sloth` will check parameters both before and after API processing, blocking malicious API request and filtering out unprivileged content. For example, administrators can set permissions to restrict the network type and IP range for creation. And the response can also be filtered, if user is requesting resources of others.


## Security Policy Syntax
`Sloth` has defined its own security policy syntax. It's `IF ELSE` style syntax, flexibly describing any security policies that network adminitrators would define.

```bash
grammar SlothPolicyRule;

policySet : globalPolicySet? localPolicySet?;

globalPolicySet : 'GLOBAL_POLICY' '{' policyStatement* '}';

localPolicySet : 'LOCAL_POLICY' '{' localPolicyStatement* '}';

localPolicyStatement : Identifier ',' Identifier '{' policyStatement* '}';

policyStatement : Identifier statement;

statement
    :   '{' statement '}'
    |   'ACCEPT'
    |   'REJECT'
    |   'if' '(' expression ')' statement ('else' statement)?
    ;

expression
    :   '(' expression ')'
    |   expression ('<=' | '>=' | '>' | '<') expression
    |   expression ('==' | '!=') expression
    |   expression '&&' expression
    |   expression '||' expression
    |   expression 'REG' expression
    |   primary
    ;

primary
    :   jsonpath
    |   slothPredefined
    |   literal
    ;

jsonpath : '$.' dotExpression ('.' dotExpression)*;

dotExpression : identifierWithQualifier | Identifier;

identifierWithQualifier
    : Identifier '[]'
    | Identifier '[' IntegerLiteral ']'
    | Identifier '[?(' queryExpression ')]'
    ;

queryExpression
    :   queryExpression ('&&' queryExpression)+
    |   queryExpression ('||' queryExpression)+
    |   '*'
    |   '@.' Identifier
    |   '@.' Identifier '>' IntegerLiteral
    |   '@.' Identifier '<' IntegerLiteral
    |   '@.length-' IntegerLiteral
    |   '@.' Identifier '==' IntegerLiteral
    |   '@.' Identifier '==\'' IntegerLiteral '\''
    ;

slothPredefined
    :   'sloth.subject.' ('role' | 'user_id')
    |   'sloth.action.' ('method' | 'url' | 'query_string')
    |   'sloth.environment.' ('date' | 'time' | 'day_of_week')
    ;

literal
    :   IntegerLiteral
    |   FloatLiteral
    |   StringLiteral
    |   BooleanLiteral
    |   NullLiteral
    ;

IntegerLiteral : NonzeroDigit Digit*;

FloatLiteral : Digit* '.' Digit*;

StringLiteral : '"' SingleCharacter+ '"';

BooleanLiteral : 'true' | 'false';

NullLiteral : 'null';

fragment
NonzeroDigit : [1-9];

fragment
Digit : [0-9];

fragment
SingleCharacter : ~["\\];

GLOBAL_POLICY : 'GLOBAL_POLICY';
LOCAL_POLICY : 'LOCAL_POLICY';
ACCEPT : 'ACCEPT';
REJECT : 'REJECT';
LBRACE : '{';
RBRACE : '}';
IF : 'if';
ELSE : 'else';
EQUAL : '==';
NOTEQUAL : '!=';
LT : '<';
GT : '>';
LE : '<=';
GE : '>=';
AND : '&&';
OR : '||';
REGULAR : 'REG';


Identifier :Letter LetterOrDigit*;

fragment
Letter : [a-zA-Z$_];

fragment
LetterOrDigit : [a-zA-Z0-9$_];

WS  : [ \t\r\n\u000C]+ -> skip;

COMMENT : '/*' .*? '*/' -> skip;

LINE_COMMENT : '//' ~[\r\n]* -> skip;
```


## Configuration

`Sloth` has a configuration file storing policies The configuration file is located at `/etc/sloth-policy`. `sloth-policy` file can be imported via karaf command line `sloth:reload` or you can reload from other configuration files, e.g. `sloth:reload /etc/sloth-policy`, which means `Sloth` is able to reload configuration at any time from any where.

The following is an example configuration file.

```bash
/*
 * This is an example an example policy file for Sloth Access Control
 * Author: Libin Song, Northwestern University
 *
 * There are two types of policies: global and local. Global policies
 * are intended for all requests. When a request comes in, it will be
 * checked against all of the global policies. While local policies
 * are intended for individual user only. Local policy has user-related
 * attributes: role and user_name. When a request from a certain user
 * comes in, only the related local policies of that matching role and
 * user_name will be checked.
 *
 * There are two reasons for designing these two separated policy set.
 * One is for performance, permission engine will only check global
 * policies and related local polices. It will greatly reduce the
 * policy checking burden when the policy set is large. And the other
 * more important reason is for expressiveness and simplicity. One of
 * the feature that Sloth Access Control provide is resource isolation.
 * Policies can be designed to limit user access requests on his own
 * resources. There will be plenty of policies isolating users. And
 * these polices are intended for individual user only. So, provided
 * with local policies, network administrators can group local policies
 * together, instead of specifying intended user every time.
 *
 */



/*
 * This is the pre-defined data structure that can be used anywhere
 * when designing policies.
 *
 * {
 *     "sloth": {
 *         "subject": {
 *             "role": "user",
 *             "user_name": "bob"
 *         },
 *         "action": {
 *             "method": "POST",
 *             "url": "/v2.0/networks",
 *             "query_string": ""
 *         },
 *         "environment": {
 *             "date": "2017-04-13",
 *             "time": "18:08:00",
 *             "day_of_week": "sat"
 *         }
 *     }
 * }
 *
 * The syntax for accessing attributes in sloth attributes is:
 * sloth.subject.role == "user",
 * sloth.environment.day_of_week == "sun"
 *
 */


/*
 * This is an example of Json data that may be along with request
 *
 * {
 *     "network": {
 *         "segments": [
 *             {
 *                 "provider:segmentation_id": 2,
 *                 "provider:physical_network": "public",
 *                 "provider:network_type": "vlan"
 *             },
 *             {
 *                 "provider:physical_network": "default",
 *                 "provider:network_type": "flat"
 *             }
 *         ],
 *         "name": "net1",
 *         "admin_state_up": true,
 *         "qos_policy_id": "6a8454ade84346f59e8d40665f878b2e"
 *     }
 * }
 *
 * The syntax for accessing attributes in Json data is:
 * $.network.admin_state_up == true
 * $.network.segments[0].provider:network_type == "flat"
 * $.network.segments[*].provider:network_type CONTAIN flat
 *
 * For detailed syntax, please refer to Jayway JsonPath
 * https://github.com/json-path/JsonPath
 *
 */


/*
 * Here is the algorithm for permission checking
 *
 * boolean permission_checking (request) {
 *     for (policy in global_policy) {
 *         result = policy.eval(request)
 *         if (result == accept) {
 *             return true
 *         } else if (result = reject) {
 *             return false
 *         }
 *     }
 *     for (policy in local_policy[request.role][request.user_name]) {
 *         result = policy.eval(request)
 *         if (result == accept) {
 *             return true
 *         } else if (reject) {
 *             return false
 *         }
 *     }
 *     return false
 * }
 *
 *
 * And here is the algorithm for policy evaluation
 *
 * Result eval (request) {
 *     if (reach ACCEPT statement) {
 *         return ACCEPT
 *     } else if (reach REJECT statement) {
 *         return REJECT
 *     } else {
 *         return UNKNOWN
 *     }
 * }
 *
 */






/*
 * GLOBAL_POLICY {
 *     ${policy_name} {
 *         if (${condition_statement}) {
 *             ACCEPT | REJECT | ${if_statement}
 *         } else if (${condition_statement}) {
 *             ACCEPT | REJECT | ${if_statement}
 *         } else {
 *             ACCEPT | REJECT | ${if_statement}
 *         }
 *     }
 * }
 */
GLOBAL_POLICY {
    admin_accept_all {
        if (sloth.subject.role == "admin") {
            ACCEPT
        }
    }

    block_after_10pm {
        if (sloth.subject.role != "admin" &&
            (sloth.environment.time > "23:59:00" || sloth.environment.time < "00:10:00")) {
            REJECT
        }
    }

    scheduled_maintenance {
        if (sloth.subject.role != "admin" && sloth.environment.day_of_week == "sun") {
            REJECT
        }
    }

    all_can_get {
        if (sloth.action.method == "GET") {
            ACCEPT
        }
    }
}




/*
 * LOCAL_POLICY {
 *     ${role}, ${user_name} {
 *         ${policy_name} {
 *             if (${condition_statement}) {
 *                 ACCEPT | REJECT | ${if_statement}
 *             } else if (${condition_statement}) {
 *                 ACCEPT | REJECT | ${if_statement}
 *             } else {
 *                 ACCEPT | REJECT | ${if_statement}
 *             }
 *         }
 *     }
 * }
 */

LOCAL_POLICY {
    admin, admin {
        no_local_policy {
            ACCEPT
        }
    }

    user, Lily {
        only_get {
            if (sloth.action.method == "GET") {
                    ACCEPT
                } else if (sloth.action.method == "POST") {
                    REJECT
                } else if (sloth.action.method == "PUT") {
                    REJECT
                } else if (sloth.action.method == "DELETE") {
                    REJECT
                }
        }
    }

    user, Gary {
        network_constraints {
            if (sloth.action.url REG "/v2[.]0/networks/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.network.port_security_enabled == true ) {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        port_constraints {
            if (sloth.action.url REG "/v2[.]0/ports/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        trunk_constraints {
            if (sloth.action.url REG "/v2[.]0/trunks/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.trunk.name == null) {
                        REJECT
                    } else {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    REJECT
                }
            }
        }

        floatingip_constraints {
            if (sloth.action.url REG "/v2[.]0/floatingips/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    REJECT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        router_constraints {
            if (sloth.action.url REG "/v2[.]0/routers/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.router.external_gateway_info == null) {
                        REJECT
                    } else {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        subnet_constraints {
            if (sloth.action.url REG "/v2[.]0/subnets/?.*") {
                if (sloth.action.method == "POST") {
                    if (($.subnet.ip_version == 6) && ($.subnet.ipv6_address_mode == "dhcpv6-stateful")) {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        firewall_policy_constraints {
            if (sloth.action.url REG "/v2[.]0/fw/firewall_policies/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        firewall_rule_constraints {
            if (sloth.action.url REG "/v2[.]0/fw/firewall_rules/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.firewall_rule.ip_version == 4 ) {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        firewall_constraints {
            if (sloth.action.url REG "/v2[.]0/fw/firewals/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.firewall.admin_state_up == true ) {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        security_group_rule_constraints {
            if (sloth.action.url REG "/v2[.]0/security-group-rules/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.security_group_rule.ethertype == "IPv6") {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        security_group_constraints {
            if (sloth.action.url REG "/v2[.]0/security-groups/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    REJECT
                } else if (sloth.action.method == "DELETE") {
                    REJECT
                }
            }
        }

        metering_label_constraints {
            if (sloth.action.url REG "/v2[.]0/metering/metering-labels/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    REJECT
                }
            }
        }

        metering_label_rule_constraints {
            if (sloth.action.url REG "/v2[.]0/metering/metering-label-rules/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.metering_label_rule.remote_ip_prefix == "10.0.1.0/24") {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        qos_policy_constraints {
            if (sloth.action.url REG "/v2[.]0/qos/policies/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        loadbalancer_constraints {
            if (sloth.action.url REG "/v2[.]0/lbaas/loadbalancers/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    REJECT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        loadbalancer_pool_constraints {
            if (sloth.action.url REG "/v2[.]0/lbaas/pools/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.pool.lb_algorithm == "LEAST_CONNECTIONS") {
                        REJECT
                    } else {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        loadbalancer_healthmonitor_constraints {
            if (sloth.action.url REG "/v2[.]0/lbaas/healthmonitors/?.*") {
                if (sloth.action.method == "POST") {
                    if ($.healthmonitor.http_method == "DELETE") {
                        ACCEPT
                    }
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    REJECT
                }
            }
        }

        bgpvpn_constraints {
            if (sloth.action.url REG "/v2[.]0/bgpvpns/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    REJECT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        gateway_constraints {
            if (sloth.action.url REG "/v2[.]0/l2-gateways/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        gateway_connection_constraints {
            if (sloth.action.url REG "/v2[.]0/l2gateway-connections/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        vpnservice_constraints {
            if (sloth.action.url REG "/v2[.]0/vpn/vpnservices/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        SFCFlowClassifier_constraints {
            if (sloth.action.url REG "/v2[.]0/sfc/flowclassifiers/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        SFCPortChain_constraints {
            if (sloth.action.url REG "/v2[.]0/sfc/portchains/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        SFCPortPair_constraints {
            if (sloth.action.url REG "/v2[.]0/sfc/portpairs/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }

        SFCPortPairGroup_constraints {
            if (sloth.action.url REG "/v2[.]0/sfc/portpairgroups/?.*") {
                if (sloth.action.method == "POST") {
                    ACCEPT
                } else if (sloth.action.method == "PUT") {
                    ACCEPT
                } else if (sloth.action.method == "DELETE") {
                    ACCEPT
                }
            }
        }
    }

}

```

## Distributed Deployment

`Sloth` can be distributed deployed in OpenDaylight (ODL). OpenDaylight provides distributed data store. All of the ODL instances have the same view of data store. Any change of data on any ODL instances will be seen by all of the ODL instances. `Sloth` extensively utilizes ODL data store to maintain the in-memory policy consistency among multiple `Sloth` instances. `Sloth` keeps a `Listener` on the policy data in data store, and this `Listener` is used to update in-memory policy. In another word, this `Listener` is responsible for maintaining the in-memory policy data consistent with policy data in ODL data store. Thus, as long as the policy data in ODL data store is consistent among ODL controllers (which is guaranteed by ODL data store), the in-memory policy data is also consistent among `Sloth` instances on ODL controllers.

And , this feature also enables `Sloth` support runtime policy update.

## Note

1. Currently, `Sloth` is compatible with 1.3.0-SNAPSHOT opendaylight-startup-archetype.
