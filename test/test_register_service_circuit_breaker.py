import unittest

from services.register_service import _systemic_failure_family


class RegisterServiceCircuitBreakerTests(unittest.TestCase):
    def test_groups_authorization_state_failures(self):
        self.assertEqual(
            _systemic_failure_family("authorization_state_not_signup: landed=email_verification"),
            "authorization_state",
        )
        self.assertEqual(_systemic_failure_family("code=invalid_auth_step"), "authorization_state")

    def test_groups_sentinel_layout_failures(self):
        self.assertEqual(
            _systemic_failure_family("sentinel_sdk_helper_failed: unsupported_sdk_layout"),
            "sentinel_sdk",
        )

    def test_ignores_non_systemic_mail_failure(self):
        self.assertEqual(_systemic_failure_family("等待注册验证码超时"), "")


if __name__ == "__main__":
    unittest.main()
