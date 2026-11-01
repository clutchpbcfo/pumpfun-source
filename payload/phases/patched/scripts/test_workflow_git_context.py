"""The explicit workflow repository survives real enclosing Git hooks."""
import importlib.util
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'workflow_git_context_probe', REPO / 'research/workflow-git-context-20261101/probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class WorkflowGitContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = probe.reproduce(REPO)

    def test_valid_retained_workflow_is_fully_checked_in_each_context(self):
        for row in self.proof['rows']:
            if row['state'] != 'present':
                continue
            with self.subTest(form=row['form'], context=row['context']):
                self.assertEqual(row['exit'], 0, row['stderr'])
                self.assertEqual(row['report']['checked_references'], 4)
                self.assertEqual(row['report']['new_missing'], [])

    def test_private_deletion_fails_in_each_context(self):
        for row in self.proof['rows']:
            if row['state'] != 'missing':
                continue
            with self.subTest(form=row['form'], context=row['context']):
                self.assertEqual(row['exit'], 1, row['stderr'])
                self.assertEqual(row['report']['checked_references'], 4)
                self.assertEqual(len(row['report']['new_missing']), 4)
                self.assertEqual({x[2] for x in row['report']['new_missing']}, {probe.SCRIPT.as_posix()})

    def test_hook_routing_is_genuine_and_inputs_remain_unchanged(self):
        routed = [row for row in self.proof['rows'] if row['context'] == 'routed_hook']
        self.assertTrue(all(row['routing']['GIT_DIR'] == 'OWNED/hook-caller/.git' for row in routed))
        self.assertTrue(self.proof['private_workflow_unchanged'])
        self.assertTrue(self.proof['retained_repository_inputs_unchanged'])


if __name__ == '__main__':
    unittest.main()
