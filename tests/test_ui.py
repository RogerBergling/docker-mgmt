"""UI formatting and prompt tests."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from docker_mgmt.ui import QuitApp, UI


class UITests(unittest.TestCase):
    def test_table_truncates_and_renders(self) -> None:
        ui = UI(color=False)
        table = ui.table(
            ["NAME", "IMAGE"],
            [["a" * 100, "nginx:1.27"]],
            max_widths=[30, 20],
        )
        self.assertIn("NAME", table)
        self.assertIn("nginx:1.27", table)
        self.assertTrue(all(len(line) <= 120 for line in table.splitlines()))

    def test_choose_number(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", side_effect=["2"]), redirect_stdout(io.StringIO()):
            value = ui.choose("Pick", [("one", 1), ("two", 2)])
        self.assertEqual(value, 2)

    def test_choose_filter_then_select(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", side_effect=["/two", "1"]), redirect_stdout(io.StringIO()):
            value = ui.choose("Pick", [("one", 1), ("two", 2)])
        self.assertEqual(value, 2)

    def test_choose_back(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", side_effect=["0"]), redirect_stdout(io.StringIO()):
            self.assertIsNone(ui.choose("Pick", [("one", 1)]))

    def test_choose_quit(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", side_effect=["q"]), redirect_stdout(io.StringIO()):
            with self.assertRaises(QuitApp):
                ui.choose("Pick", [("one", 1)])

    def test_confirm(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", side_effect=["yes"]):
            self.assertTrue(ui.confirm("Continue?"))
        with patch("builtins.input", side_effect=[""]):
            self.assertFalse(ui.confirm("Continue?"))

    def test_confirm_phrase(self) -> None:
        ui = UI(color=False)
        with patch("builtins.input", return_value="UPDATE"), redirect_stdout(io.StringIO()):
            self.assertTrue(ui.confirm_phrase("Danger", "UPDATE"))
        with patch("builtins.input", return_value="update"), redirect_stdout(io.StringIO()):
            self.assertFalse(ui.confirm_phrase("Danger", "UPDATE"))


if __name__ == "__main__":
    unittest.main()
