"""Minimal terminal UI: tables, numbered menus, confirmations.

No curses or third-party TUI library is used. Menus support paging and text
filtering so a server with hundreds of containers remains usable.
"""

from __future__ import annotations

import math
import shutil
import textwrap
from typing import Generic, Optional, Sequence, TypeVar

from .runner import sanitize_text


class QuitApp(Exception):
    """Raised when the operator asks to leave the interactive menu."""


T = TypeVar("T")


class UI(Generic[T]):
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"

    def __init__(self, color: bool = True, page_size: int = 20) -> None:
        self.color = color
        self.page_size = max(5, page_size)

    @staticmethod
    def _safe(text: object) -> str:
        return sanitize_text(str(text), max_length=16000)

    def _paint(self, text: object, code: str) -> str:
        text = self._safe(text)
        if not self.color:
            return text
        return f"{code}{text}{self.RESET}"

    def header(self, title: str) -> None:
        title = self._safe(title)
        line = "=" * max(8, len(title))
        print()
        print(self._paint(title, self.BOLD))
        print(self._paint(line, self.DIM))

    def section(self, title: str) -> None:
        print()
        print(self._paint(title, self.BOLD))

    def info(self, text: str) -> None:
        print(self._safe(text))

    def success(self, text: str) -> None:
        print(self._paint(text, self.GREEN))

    def warn(self, text: str) -> None:
        print(self._paint(text, self.YELLOW))

    def error(self, text: str) -> None:
        print(self._paint(text, self.RED))

    def dim(self, text: str) -> None:
        print(self._paint(text, self.DIM))

    def bullets(self, values: Sequence[str], prefix: str = "  - ") -> None:
        for value in values:
            print(prefix + sanitize_text(str(value), max_length=4000))

    def key_values(self, values: Sequence[tuple[str, object]], indent: str = "  ") -> None:
        if not values:
            return
        cleaned = [
            (
                sanitize_text(str(key), max_length=200),
                sanitize_text(str(value), max_length=4000),
            )
            for key, value in values
        ]
        width = max(len(key) for key, _ in cleaned)
        for key, value in cleaned:
            print(f"{indent}{key.ljust(width)} : {value}")

    def pause(self, message: str = "Press Enter to continue...") -> None:
        try:
            input(message)
        except EOFError as exc:
            raise QuitApp from exc

    def prompt(self, message: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            value = input(f"{message}{suffix}: ").strip()
        except EOFError as exc:
            raise QuitApp from exc
        return value or default

    def confirm(self, message: str, *, default: bool = False) -> bool:
        marker = "[Y/n]" if default else "[y/N]"
        while True:
            try:
                value = input(f"{message} {marker}: ").strip().lower()
            except EOFError as exc:
                raise QuitApp from exc
            if not value:
                return default
            if value in {"y", "yes"}:
                return True
            if value in {"n", "no"}:
                return False
            self.warn("Please answer y or n.")

    def confirm_phrase(self, message: str, phrase: str) -> bool:
        self.warn(message)
        try:
            value = input(f'Type "{phrase}" to continue, or press Enter to cancel: ')
        except EOFError as exc:
            raise QuitApp from exc
        return value.strip() == phrase

    def choose(
        self,
        title: str,
        options: Sequence[tuple[str, T]],
        *,
        allow_back: bool = True,
        page_size: Optional[int] = None,
        back_label: str = "Back",
    ) -> Optional[T]:
        """Display a paged, filterable numbered menu.

        Returns the selected value, or None for the back/exit entry. Raises
        QuitApp when the operator enters q.
        """

        self.header(title)
        if not options:
            self.info("No entries.")
            if allow_back:
                self.pause()
            return None

        size = page_size or self.page_size
        page = 0
        filter_text = ""
        while True:
            filtered = [
                (
                    index,
                    self._menu_text(label),
                    value,
                )
                for index, (label, value) in enumerate(options)
                if not filter_text
                or filter_text.lower() in self._menu_text(label).lower()
            ]
            pages = max(1, math.ceil(len(filtered) / size))
            page = max(0, min(page, pages - 1))
            start = page * size
            visible = filtered[start : start + size]

            if filter_text:
                self.dim(f"Filter: {filter_text!r} ({len(filtered)} match(es))")
            if pages > 1:
                self.dim(f"Page {page + 1}/{pages}")
            for local_index, (_, label, _) in enumerate(visible, start=start + 1):
                print(f"  {local_index:>3}. {self._truncate(str(label), self._menu_width())}")
            if not visible:
                self.warn("No entries match the filter.")

            hints = ["number = select"]
            if pages > 1:
                hints.extend(["n = next page", "p = previous page"])
            hints.extend(["/text = filter", "r = reset filter", "q = quit"])
            if allow_back:
                hints.append(f"0 = {back_label.lower()}")
            else:
                hints.append("0 = exit")
            self.dim("  " + " | ".join(hints))

            try:
                value = input("Choice: ").strip()
            except EOFError as exc:
                raise QuitApp from exc
            lowered = value.lower()
            if lowered == "q":
                raise QuitApp
            if lowered == "0":
                return None
            if lowered in {"n", "next"}:
                if page + 1 < pages:
                    page += 1
                continue
            if lowered in {"p", "prev", "previous"}:
                if page > 0:
                    page -= 1
                continue
            if lowered == "r":
                filter_text = ""
                page = 0
                continue
            if lowered.startswith("/"):
                filter_text = value[1:].strip()
                page = 0
                continue
            if lowered in {"?", "help"}:
                self.info(
                    "Enter a number to select. Use /text to filter, n/p to page, "
                    "r to reset, 0 to go back, q to quit."
                )
                continue
            try:
                selected = int(value)
            except ValueError:
                self.warn("Enter a menu number, or use one of the shown commands.")
                continue
            if 1 <= selected <= len(filtered):
                return filtered[selected - 1][2]
            self.warn("That number is outside the current list.")

    def table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[object]],
        *,
        max_widths: Optional[Sequence[int]] = None,
        min_widths: Optional[Sequence[int]] = None,
    ) -> str:
        columns = len(headers)
        if columns == 0:
            return ""
        string_rows = [
            [
                self._one_line(str(cell)) if index < columns else ""
                for index, cell in enumerate(row)
            ]
            for row in rows
        ]
        natural = [len(str(headers[i])) for i in range(columns)]
        for row in string_rows:
            for index in range(columns):
                natural[index] = max(natural[index], len(row[index]))
        widths = list(natural)
        if max_widths:
            for index, width in enumerate(max_widths[:columns]):
                if width > 0:
                    widths[index] = min(widths[index], width)
        minimum = list(min_widths or [len(str(headers[i])) for i in range(columns)])
        widths = [max(widths[i], max(1, minimum[i])) for i in range(columns)]

        terminal = max(50, shutil.get_terminal_size(fallback=(120, 24)).columns)
        while sum(widths) + 3 * (columns - 1) > terminal:
            candidates = [
                (widths[i], i)
                for i in range(columns)
                if widths[i] > max(1, minimum[i])
            ]
            if not candidates:
                break
            _, index = max(candidates)
            widths[index] -= 1

        def render(row: Sequence[str]) -> str:
            cells = [
                self._truncate(row[i] if i < len(row) else "", widths[i]).ljust(
                    widths[i]
                )
                for i in range(columns)
            ]
            return " | ".join(cells).rstrip()

        header = render([str(item) for item in headers])
        separator = "-+-".join("-" * width for width in widths)
        lines = [header, separator]
        lines.extend(render(row) for row in string_rows)
        return "\n".join(lines)

    def print_table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[object]],
        *,
        max_widths: Optional[Sequence[int]] = None,
        min_widths: Optional[Sequence[int]] = None,
    ) -> None:
        print(
            self.table(
                headers,
                rows,
                max_widths=max_widths,
                min_widths=min_widths,
            )
        )

    def wrapped(self, text: str, indent: str = "  ") -> str:
        width = max(40, shutil.get_terminal_size(fallback=(120, 24)).columns - 3)
        return "\n".join(
            textwrap.fill(
                paragraph,
                width=width,
                initial_indent=indent,
                subsequent_indent=indent,
            )
            for paragraph in str(text).splitlines() or [""]
        )

    @staticmethod
    def _one_line(value: str) -> str:
        value = sanitize_text(value, max_length=4000)
        return " ".join(value.replace("\t", " ").splitlines())

    @staticmethod
    def _menu_text(value: object) -> str:
        return " ".join(
            sanitize_text(str(value), max_length=4000).replace("\t", " ").splitlines()
        )

    @staticmethod
    def _truncate(value: str, width: int) -> str:
        if width <= 3:
            return value[:width]
        if len(value) <= width:
            return value
        return value[: width - 3] + "..."

    @staticmethod
    def _menu_width() -> int:
        return max(40, shutil.get_terminal_size(fallback=(120, 24)).columns - 12)
