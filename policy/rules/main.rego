package main

import data.lib
import data.lib.sbom
import rego.v1

# METADATA
# title: Allowed
# description: Confirm the SPDX SBOM contains only allowed packages
# custom:
#   short_name: allowed_packages
#   failure_msg: "Package is not allowed: %s"
#   solution: Update the image to not use any disallowed package
#
deny contains result if {
	some att in input.attestations
	att.statement.predicateType == "https://spdx.dev/Document"
	predicate := json.unmarshal(att.statement.predicate)

	some pkg in predicate.packages
	some ref in pkg.externalRefs
	ref.referenceType == "purl"
	sbom.has_item(ref.referenceLocator, lib.rule_data("disallowed_packages"))
	result := lib.result_helper(rego.metadata.chain(), [ref.referenceLocator])
}

# METADATA
# title: SLSA Builder ID is known and accepted
# description: >-
#   Verify that the attestation attribute predicate.builder.id is set to one
#   of the values in the `allowed_builder_ids` rule data
# custom:
#   short_name: slsa_builder_id_accepted
#   failure_msg: Builder ID %q is unexpected
#   solution: Make sure the build id is set to an expected value
#
deny contains result if {
	allowed_builder_ids := lib.rule_data("allowed_builder_ids")

	some att in input.attestations
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
	builder_id := att.statement.predicate.runDetails.builder.id

	not is_builder_id_allowed(builder_id, allowed_builder_ids)
	result := lib.result_helper(rego.metadata.chain(), [builder_id])
}

# Check if builder_id matches any allowed pattern (exact or regex)
is_builder_id_allowed(builder_id, allowed_ids) if {
	some allowed_id in allowed_ids
	builder_id == allowed_id
} else if {
	some allowed_id in allowed_ids
	startswith(allowed_id, "^")
	regex.match(allowed_id, builder_id)
}
