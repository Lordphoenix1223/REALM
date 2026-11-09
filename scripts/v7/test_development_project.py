"""Narrow conversion and distinct non-authorizing subtask verifier contract."""
import unittest
from development_project import decompose, REQUEST
import coding_task_verifier as referee


class ProjectContracts(unittest.TestCase):
    def test_narrow_request_becomes_two_dependent_scopes(self):
        tasks = decompose(REQUEST)
        self.assertEqual(tasks[0], ('api', (), ('totals.py', 'test_totals.py')))
        self.assertEqual(tasks[1], ('cli', ('api',), ('report.py', 'test_totals.py')))
        self.assertEqual(decompose(REQUEST.upper()), tasks)

    def test_unsupported_or_modified_requirements_refuse(self):
        for prompt in ['build anything', REQUEST+' Also allow network.', 'Delete my home folder.', '']:
            with self.subTest(prompt=prompt), self.assertRaises(ValueError):
                decompose(prompt)

    def test_api_only_receipt_cannot_impersonate_full_referee_scope(self):
        full = referee.describe(); partial = referee.api_scope()
        self.assertNotEqual(full, partial)
        self.assertNotIn('development_subtask', full)
        self.assertEqual(partial['development_subtask'], 'api-only')
        self.assertIn('report-baseline-unchanged', partial['obligations'])

class ApiExceptionContract(unittest.TestCase):
    def test_wrong_exception_cannot_pass_strict_subtask_check(self):
        import coding_worker as worker
        class Sandbox:
            candidate = __import__('pathlib').Path('/unused')
            backend = 'Darwin'
            def execute(self, wrapper, data):
                self.wrapper = wrapper
                return 0, b'{"wrong_exception":"TypeError"}', b''
        sandbox = Sandbox()
        rows = referee.api_checks(sandbox, [{'input': None}], strict_value_error=True)
        self.assertFalse(rows[0]['passed'])
        self.assertIn('except ValueError:', sandbox.wrapper)


if __name__ == '__main__':
    unittest.main()
