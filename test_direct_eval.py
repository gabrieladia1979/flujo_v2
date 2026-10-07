"""Guard against invalid paired splits and threshold selection on test data."""

import unittest

from scripts.direct_eval import exact_saved_splits, score_metrics, threshold_on_validation


class DirectEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {'id': 'a', 'group': 'ga', 'label': 0},
            {'id': 'b', 'group': 'gb', 'label': 1},
            {'id': 'c', 'group': 'gc', 'label': 0},
            {'id': 'd', 'group': 'gd', 'label': 1},
            {'id': 'e', 'group': 'ge', 'label': 0},
            {'id': 'f', 'group': 'gf', 'label': 1},
        ]
        self.saved = {
            'train': [{'id': 'a'}, {'id': 'b'}],
            'validation': [{'id': 'c'}, {'id': 'd'}],
            'test': [{'id': 'e'}, {'id': 'f'}],
        }

    def test_exact_saved_ids_and_group_separation(self):
        result = exact_saved_splits(self.rows, self.saved)
        self.assertEqual([self.rows[i]['id'] for i in result['test']], ['e', 'f'])
        self.rows[-1]['group'] = 'gb'
        with self.assertRaisesRegex(ValueError, 'cross-split'):
            exact_saved_splits(self.rows, self.saved)

    def test_missing_saved_row_fails(self):
        self.rows.append({'id': 'g', 'group': 'gg', 'label': 0})
        with self.assertRaisesRegex(ValueError, 'cover exactly'):
            exact_saved_splits(self.rows, self.saved)

    def test_threshold_respects_validation_false_positive_cap(self):
        threshold = threshold_on_validation([0, 0, 1, 1], [0.1, 0.7, 0.6, 0.9], 0.0)
        self.assertGreater(threshold, 0.7)
        metrics = score_metrics([0, 0, 1, 1], [0.1, 0.7, 0.6, 0.9], threshold)
        self.assertEqual(metrics['confusion_matrix']['false_positive'], 0)
        self.assertEqual(metrics['confusion_matrix']['false_negative'], 1)


if __name__ == '__main__':
    unittest.main()
