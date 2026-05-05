package terraform.security_groups

import rego.v1

public_cidrs := {"0.0.0.0/0", "::/0"}

deny contains msg if {
    some sg_name                                              # (1)
    sg_entries := input.resource.aws_security_group[sg_name] # (2)
    sg         := sg_entries[_]                              # (3)
    ingress    := sg.ingress[_]                              # (4)
    cidr       := ingress.cidr_blocks[_]                     # (5)
    cidr in public_cidrs                                     # (6)
    msg := sprintf(
        "FAIL [sg-no-public-ingress]: Security group '%s' permite ingreso desde '%s'.",
        [sg_name, cidr],
    )
}

deny contains msg if {
    some sg_name
    sg_entries := input.resource.aws_security_group[sg_name]
    sg         := sg_entries[_]
    ingress    := sg.ingress[_]
    cidr       := ingress.ipv6_cidr_blocks[_]
    cidr in public_cidrs
    msg := sprintf(
        "FAIL [sg-no-public-ingress-ipv6]: Security group '%s' permite ingreso IPv6 desde '%s'.",
        [sg_name, cidr],
    )
}

deny contains msg if {
    some rule_name
    rule_entries := input.resource.aws_security_group_rule[rule_name]
    rule         := rule_entries[_]
    rule.type    == "ingress"
    cidr         := rule.cidr_blocks[_]
    cidr in public_cidrs
    msg := sprintf(
        "FAIL [sg-rule-no-public-ingress]: Regla de SG '%s' permite ingreso desde '%s'.",
        [rule_name, cidr],
    )
}
