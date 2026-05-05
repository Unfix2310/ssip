"""
XACML 3.0 Compiler: converts ResolvedEntities → XACML XML policy.
Pure deterministic template. Zero LLM involvement.
"""

from __future__ import annotations

import logging
import re
import uuid
import xml.dom.minidom as minidom
from typing import Optional
from xml.etree.ElementTree import Element, SubElement, tostring

from ..exceptions import PolicyCompilationError
from ..schema import Conditions
from . import PolicyCompiler, ResolvedEntities

logger = logging.getLogger(__name__)

# XACML 3.0 namespaces
XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
XACML_POLICY_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"

# Standard XACML combining algorithms
RULE_COMBINING = "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"

# Standard XACML attribute categories
SUBJECT_CATEGORY = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
ACTION_CATEGORY = "urn:oasis:names:tc:xacml:3.0:attribute-category:action"
RESOURCE_CATEGORY = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
ENVIRONMENT_CATEGORY = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment"


def _extract_arn(cedar_entity: str) -> str:
    """Extract raw ARN from Cedar entity string."""
    match = re.search(r'"([^"]+)"', cedar_entity)
    return match.group(1) if match else cedar_entity


def _prettify_xml(element: Element) -> str:
    """Convert an ElementTree element to a pretty-printed XML string."""
    rough = tostring(element, encoding="unicode", xml_declaration=False)
    parsed = minidom.parseString(rough)
    pretty = parsed.toprettyxml(indent="  ")
    # Remove the XML declaration added by minidom (we add our own)
    lines = pretty.split("\n")
    if lines and lines[0].startswith("<?xml"):
        lines = lines[1:]
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + "\n".join(lines)


def _add_match(
    any_of: Element,
    match_id: str,
    attribute_value: str,
    attribute_id: str,
    category: str,
    data_type: str = "http://www.w3.org/2001/XMLSchema#string",
) -> None:
    """Add an XACML Match element to an AnyOf/AllOf chain."""
    all_of = SubElement(any_of, "AllOf")
    match = SubElement(all_of, "Match", MatchId=match_id)

    attr_val = SubElement(
        match, "AttributeValue",
        DataType=data_type,
    )
    attr_val.text = attribute_value

    SubElement(
        match, "AttributeDesignator",
        AttributeId=attribute_id,
        Category=category,
        DataType=data_type,
        MustBePresent="true",
    )


class XACMLCompiler(PolicyCompiler):
    """Deterministic XACML 3.0 policy compiler."""

    format_name = "xacml"

    def compile(
        self,
        resolved: ResolvedEntities,
        conditions: Optional[Conditions] = None,
    ) -> str:
        """Produce an XACML 3.0 policy XML from resolved entities."""
        try:
            effect = getattr(resolved, "effect", "permit")
            principal_arn = _extract_arn(resolved.principal)
            resource_arn = _extract_arn(resolved.resource)

            policy_id = f"policy-{uuid.uuid4().hex[:12]}"
            rule_id = f"rule-{uuid.uuid4().hex[:12]}"

            # Map effect
            xacml_effect = "Permit" if effect == "permit" else "Deny"

            # ── Policy root ───────────────────────────────────────────────────
            policy = Element(
                "Policy",
                xmlns=XACML_NS,
                PolicyId=policy_id,
                RuleCombiningAlgId=RULE_COMBINING,
                Version="1.0",
            )

            # Description
            desc = SubElement(policy, "Description")
            desc.text = (
                f"{xacml_effect} {resolved.action} access for "
                f"{principal_arn} on {resource_arn}"
            )

            # Target (empty — rule-level targeting)
            SubElement(policy, "Target")

            # ── Rule ──────────────────────────────────────────────────────────
            rule = SubElement(policy, "Rule", RuleId=rule_id, Effect=xacml_effect)

            target = SubElement(rule, "Target")

            # Subject match
            subject_any = SubElement(target, "AnyOf")
            _add_match(
                subject_any,
                match_id="urn:oasis:names:tc:xacml:1.0:function:string-equal",
                attribute_value=principal_arn,
                attribute_id="urn:oasis:names:tc:xacml:1.0:subject:subject-id",
                category=SUBJECT_CATEGORY,
            )

            # Action match
            action_any = SubElement(target, "AnyOf")
            _add_match(
                action_any,
                match_id="urn:oasis:names:tc:xacml:1.0:function:string-equal",
                attribute_value=resolved.action,
                attribute_id="urn:oasis:names:tc:xacml:1.0:action:action-id",
                category=ACTION_CATEGORY,
            )

            # Resource match
            resource_any = SubElement(target, "AnyOf")
            _add_match(
                resource_any,
                match_id="urn:oasis:names:tc:xacml:1.0:function:string-equal",
                attribute_value=resource_arn,
                attribute_id="urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                category=RESOURCE_CATEGORY,
            )

            # ── Conditions ────────────────────────────────────────────────────
            if conditions and (conditions.network_restriction or conditions.time_restriction):
                condition = SubElement(rule, "Condition")
                apply_and = SubElement(
                    condition, "Apply",
                    FunctionId="urn:oasis:names:tc:xacml:1.0:function:and",
                )

                if conditions.network_restriction:
                    apply_eq = SubElement(
                        apply_and, "Apply",
                        FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal",
                    )
                    val = SubElement(
                        apply_eq, "AttributeValue",
                        DataType="http://www.w3.org/2001/XMLSchema#string",
                    )
                    val.text = conditions.network_restriction
                    SubElement(
                        apply_eq, "AttributeDesignator",
                        AttributeId="urn:oasis:names:tc:xacml:3.0:environment:source-ip",
                        Category=ENVIRONMENT_CATEGORY,
                        DataType="http://www.w3.org/2001/XMLSchema#string",
                        MustBePresent="true",
                    )

                if conditions.time_restriction:
                    apply_eq = SubElement(
                        apply_and, "Apply",
                        FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal",
                    )
                    val = SubElement(
                        apply_eq, "AttributeValue",
                        DataType="http://www.w3.org/2001/XMLSchema#string",
                    )
                    val.text = conditions.time_restriction
                    SubElement(
                        apply_eq, "AttributeDesignator",
                        AttributeId="urn:oasis:names:tc:xacml:1.0:environment:current-time",
                        Category=ENVIRONMENT_CATEGORY,
                        DataType="http://www.w3.org/2001/XMLSchema#string",
                        MustBePresent="true",
                    )

            xml_str = _prettify_xml(policy)
            logger.info("[XACMLCompiler] XACML policy generated (%d chars).", len(xml_str))
            return xml_str

        except Exception as exc:
            raise PolicyCompilationError(f"XACML compilation failed: {exc}") from exc
