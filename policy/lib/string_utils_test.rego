package lib_test

import rego.v1

import data.lib

test_quoted_values_string if {
	lib.assert_equal("'a', 'b', 'c'", lib.quoted_values_string(["a", "b", "c"]))
	lib.assert_equal("'a', 'b', 'c'", lib.quoted_values_string({"a", "b", "c"}))
}

test_pluralize_maybe if {
	test_cases := [
		{
			"singular": "mouse",
			"plural": "mice",
			"expected": ["mouse", "mice", "mice"],
		},
		{
			"singular": "bug",
			"plural": "",
			"expected": ["bug", "bugs", "bugs"],
		},
	]

	every t in test_cases {
		result := [lib.pluralize_maybe(s, t.singular, t.plural) | some s in [{"a"}, {"a", "b"}, {}]]
		lib.assert_equal(t.expected, result)
	}
}
