import unittest

from reverse_lab.function_browser import (
    build_function_index, search_functions, describe_function, format_function_details,
)


def report():
    return {"analysis": {
        "functions": [{"name": "main", "entry": "00401000"},
                      {"name": "process_audio", "entry": "00401100"}],
        "pseudocode": [{"name": "process_audio", "entry": "00401100",
                        "pseudocode": "void process_audio(void) { /* approximation */ }",
                        "truncated": False}],
        "call_graph": [
            {"caller": {"name": "main", "entry": "00401000"},
             "callee": {"name": "process_audio", "entry": "00401100"}},
            {"caller": {"name": "process_audio", "entry": "00401100"},
             "callee": {"name": "external_decoder", "entry": "00401200"}},
            {"caller": {"name": "main", "entry": "00401000"},
             "callee": {"name": "process_audio", "entry": "00401100"}},
        ],
    }}


class FunctionBrowserTests(unittest.TestCase):
    def test_unifies_functions_pseudocode_and_call_graph(self):
        index = build_function_index(report())
        self.assertEqual(set(index), {"00401000", "00401100", "00401200"})
        details = describe_function(index, "00401100")
        self.assertEqual(details["name"], "process_audio")
        self.assertIn("void process_audio", details["pseudocode"])
        self.assertEqual(details["calls_in"], [{"name": "main", "entry": "00401000"}])
        self.assertEqual(details["calls_out"], [{"name": "external_decoder", "entry": "00401200"}])

    def test_search_by_name_and_address_case_insensitively(self):
        index = build_function_index(report())
        self.assertEqual(search_functions(index, "AuDiO"), [("process_audio", "00401100")])
        self.assertEqual(search_functions(index, "00401200"), [("external_decoder", "00401200")])

    def test_builds_catalog_when_only_call_graph_exported(self):
        index = build_function_index({"analysis": {"call_graph": report()["analysis"]["call_graph"]}})
        self.assertEqual(len(index), 3)
        self.assertIsNone(describe_function(index, "00401000")["pseudocode"])

    def test_skips_invalid_items_without_mutation(self):
        data = report()
        original = dict(data["analysis"]["functions"][0])
        data["analysis"]["functions"].extend([None, {"name": 10, "entry": "23"}])
        data["analysis"]["call_graph"].append({"caller": "bad", "callee": {}})
        data["analysis"]["pseudocode"].append({"name": "bad", "entry": "X", "pseudocode": 7})
        self.assertEqual(len(build_function_index(data)), 3)
        self.assertEqual(data["analysis"]["functions"][0], original)

    def test_bounds_limits_and_duplicate_calls(self):
        index = build_function_index(report(), max_edges=2)
        details = describe_function(index, "00401100", max_calls=1)
        self.assertEqual(len(details["calls_in"]), 1)
        self.assertEqual(len(details["calls_out"]), 1)
        self.assertEqual(len(search_functions(index, limit=2)), 2)
        with self.assertRaises(ValueError):
            search_functions(index, limit=0)
        with self.assertRaises(ValueError):
            build_function_index(report(), max_nodes=0)

    def test_untrusted_strings_are_bounded_and_never_interpreted(self):
        data = {"analysis": {
            "functions": [{"name": "<script>alert(1)</script>" * 500, "entry": "A"}],
            "pseudocode": [{"name": "x", "entry": "A",
                            "pseudocode": "q" * 30000, "truncated": True}],
        }}
        details = describe_function(build_function_index(data), "A")
        self.assertLessEqual(len(details["name"]), 180)
        self.assertEqual(len(details["pseudocode"]), 8000)
        self.assertIn("aproximado", format_function_details(details).lower())

    def test_unknown_function_returns_none(self):
        self.assertIsNone(describe_function(build_function_index(report()), "absent"))

    def test_plain_text_contains_related_functions_and_warning(self):
        details = describe_function(build_function_index(report()), "00401100")
        text = format_function_details(details)
        self.assertIn("external_decoder", text)
        self.assertIn("main", text)
        self.assertIn("no es el código fuente original", text)


if __name__ == "__main__":
    unittest.main()
