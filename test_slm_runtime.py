"""Focused tests for the local SLM CPU-concurrency boundary."""

import unittest
from unittest.mock import patch

from services import slm_client


class SlmRuntimeTests(unittest.TestCase):
    def test_busy_generation_uses_fallback_without_initializing_model(self):
        self.assertTrue(slm_client._slm_inference_lock.acquire(blocking=False))
        try:
            with patch.object(slm_client, "render_server_fallback", return_value="fallback") as fallback, patch.object(
                slm_client, "get_slm_instance", side_effect=AssertionError("must not initialize while busy")
            ):
                result = slm_client.generate_slm_explanation(object())
        finally:
            slm_client._slm_inference_lock.release()

        self.assertEqual(result, "fallback")
        fallback.assert_called_once()

    def test_runtime_status_exposes_single_generation_bound(self):
        status = slm_client.slm_runtime_status()
        self.assertEqual(status["max_concurrent_generations"], 1)
        self.assertIn("model_file_exists", status)
        self.assertIn("loaded", status)


if __name__ == "__main__":
    unittest.main()
