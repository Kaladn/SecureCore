import unittest

from securecore.chat.router import ChatRouter


class ChatRouterTests(unittest.TestCase):
    def test_normalize_mode_accepts_known_modes(self):
        router = ChatRouter()
        self.assertEqual(router.normalize_mode("support"), "support")
        self.assertEqual(router.normalize_mode("operations"), "operations")
        self.assertEqual(router.normalize_mode("build"), "build")

    def test_normalize_mode_defaults_unknown_values(self):
        router = ChatRouter()
        self.assertEqual(router.normalize_mode("weird"), "support")
        self.assertEqual(router.normalize_mode(""), "support")


if __name__ == "__main__":
    unittest.main()

