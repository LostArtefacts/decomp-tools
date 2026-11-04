#!/usr/bin/env python3
"""Renders decompilation progress as an SVG: docs/progress.svg.

    render_progress.py [OUTPUT]

Functions come from config/symbols.csv, limited to the game code;
their status from the build:

- named:       decompiled and matching, with a real name
- decompiled:  decompiled and matching, still with a placeholder name
               (any part of the name carries an address: Func42a670)
- nonmatching: defined in src/, not matching yet
- todo:        everything else

It reads the build and does not run one: `just progress` builds
first. It prints a bar of
the functions and one of the bytes, matched and not matching yet, and
for a PE game two of the whole original exe: its code (the game's,
the libraries' after game.game_end, and code no row covers) and its
data rows, defined once an object in exe.obj_dir defines them; then the
counts of each.

With game.format = "le", it also counts the data segments that match.
A function without a size in symbols.csv takes the one in
build/functions.csv, from `just analyze`. One with size 0 shares its
code with another, as wcc386 does for identical functions; it counts
as a function but takes no space in the treemap.
"""
import csv
import fnmatch
import glob
import html
import os
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum, auto
from itertools import groupby
from typing import Any, TypedDict

import compare
import project
from project import GAME_END

ROOT = project.ROOT
TITLE = project.config["game"]["title"]
LE = project.FORMAT == "le"
ORDER_HEADER = "By function order"
SIZE_HEADER = "By function size"
HEADER = TITLE if LE else f"{TITLE} · {project.config['game']['exe']}"


class SymbolStatus(StrEnum):
    NAMED = auto()
    DECOMPILED = auto()
    NONMATCHING = auto()
    TODO = auto()


PLACEHOLDER = re.compile(r"[A-Za-z]+[0-9a-f]{6}\b")


@dataclass
class Symbol:
    signature: str
    offset: int
    size: int
    status: SymbolStatus


def built_from_svg(path: str) -> dict[int, bool | None]:
    """Whether each function a rendering shows matched: True, False
    when it did not, None when it was not built."""
    with open(path) as f:
        svg = f.read()
    built: dict[int, bool | None] = {}
    for status, address in re.findall(r'class="(\w+)"><title>(0x[0-9a-f]+) ', svg):
        built[int(address, 16)] = {"todo": None, "nonmatching": False}.get(status, True)
    return built


def compare_built_le() -> tuple[dict[int, bool], tuple[int, int]]:
    """Whether each compiled function matches, by address, from the LE
    backend's objects; and how many data segments match, of how many."""
    import compare_le, omf
    orig = compare_le.Original(os.path.join(ROOT, compare_le.EXE))
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        by_symbol = {r["symbol"]: r for r in csv.DictReader(f) if r["symbol"]}
    built: dict[int, bool] = {}
    same = segments = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "build/obj/*.obj"))):
        for mod in omf.modules(path):
            for r in compare_le.compare_module(mod, orig, by_symbol)[0]:
                if getattr(r, "data", False):
                    same += r.ok()
                    segments += 1
                elif r.addr is not None and not r.warning:
                    built[r.addr] = built.get(r.addr, True) and r.ok()
    return built, (same, segments)


def collect_functions(built: dict[int, bool]) -> list[Symbol]:
    """The game's functions, with whether `built` (by address) has them
    matching."""
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        rows = [r for r in csv.DictReader(f) if int(r["address"], 16) < GAME_END
                and not any(fnmatch.fnmatchcase(r["name"], g) for g in project.config["game"]["progress_exclude"])]
    if LE:
        sizes = {}
        found = os.path.join(ROOT, project.FUNCTIONS)
        if os.path.exists(found):
            with open(found) as f:
                sizes = {int(r["address"], 16): r["size"] for r in csv.DictReader(f)}
        for row in rows:
            row["size"] = row["size"] or sizes.get(int(row["address"], 16), "")
    functions = []
    for row in rows:
        same = built.get(int(row["address"], 16))
        if same is None:
            status = SymbolStatus.TODO
        elif not same:
            status = SymbolStatus.NONMATCHING
        elif PLACEHOLDER.search(row["name"]):
            status = SymbolStatus.DECOMPILED
        else:
            status = SymbolStatus.NAMED
        functions.append(Symbol(
            signature=f"{row['address']} {row['name']} ({row['size'] or 0} bytes)",
            offset=int(row["address"], 16),
            size=int(row["size"] or 0),
            status=status,
        ))
    if LE:
        for f, row in zip(functions, rows):
            if not row["size"]:
                print(f"warning: no size for {f.signature}", file=sys.stderr)
        return sorted(functions, key=lambda f: f.offset)
    for f in functions:
        if not f.size:
            print(f"warning: no size for {f.signature}, left out", file=sys.stderr)
    # A function without a size has no area in the treemap.
    return sorted((f for f in functions if f.size), key=lambda f: f.offset)


def compare_built_pe() -> dict[int, bool]:
    """Whether each compiled function matches, by address: all of a
    row's symbols that were built must match."""
    built = {name: same for name, same, *_ in compare.results(compare.read_symbols())}
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        rows = list(csv.DictReader(f))
    result = {}
    for row in rows:
        symbols = [s for s in row["symbol"].split() if s in built]
        if symbols:
            result[int(row["address"], 16)] = all(built[s] for s in symbols)
    return result


DOCUMENT_MARGIN = Decimal(2)
GRID_MAX_SQUARES = 50
GRID_SQUARE_SIZE = Decimal(12)
GRID_SQUARE_MARGIN = Decimal(3)
PROGRESS_BAR_SIZE = Decimal(6)
LEGEND_SQUARE_SIZE = GRID_SQUARE_SIZE
LEGEND_SQUARE_MARGIN = GRID_SQUARE_MARGIN
LEGEND_ROW_PADDING = Decimal(3)
LEGEND_MARGIN = Decimal(15)
TEXT_SIZE = Decimal(15)
TEXT_MARGIN = Decimal(5)
LEGEND_TEXT_SIZE = Decimal(12)
SECTION_MARGIN = GRID_SQUARE_SIZE + LEGEND_MARGIN
GRID_WIDTH = (
    GRID_MAX_SQUARES * (GRID_SQUARE_SIZE + GRID_SQUARE_MARGIN)
    - GRID_SQUARE_MARGIN
)
ZERO = Decimal(0)
EPSILON = Decimal("0.1")


class SumMode(StrEnum):
    BYTES = auto()
    COUNT = auto()


@dataclass
class MyFraction:
    """Fraction that doesn't normalize (eg 8/12 doesn't become 2/3)"""

    numerator: int
    denominator: int


def format_decimal(source: Decimal) -> str:
    return str(source.quantize(Decimal("1.11"))).replace(".00", "")


def format_percent(source: MyFraction) -> str:
    return format_decimal(fraction_to_decimal(source) * 100) + "%"


def fraction_to_decimal(source: MyFraction) -> Decimal:
    return Decimal(source.numerator) / Decimal(source.denominator)


@dataclass
class Box:
    x1: Decimal
    y1: Decimal
    x2: Decimal
    y2: Decimal

    @property
    def dx(self) -> Decimal:
        return self.x2 - self.x1

    @property
    def dy(self) -> Decimal:
        return self.y2 - self.y1


@dataclass
class SquarifyResult(Box):
    item: Any


class Squarify:
    def __init__(
        self,
        items: Iterable[Any],
        key: Callable[[Any], Decimal],
        box: Box,
        normalize: bool = True,
    ) -> None:
        self.key: Callable[[Any], Decimal] = key

        if normalize:
            total_size = sum(map(key, items))
            total_area = box.dx * box.dy

            def normalized_key(item: Any) -> Decimal:
                return key(item) * total_area / total_size

            self.key = normalized_key

        self.items = list(sorted(items, key=self.key, reverse=True))
        self.box = box

    def layoutrow(self, items: Iterable[Any]) -> Iterable[SquarifyResult]:
        covered_area = sum(self.key(item) for item in items)
        dx = covered_area / self.box.dy
        y = self.box.y1
        for item in items:
            yield SquarifyResult(
                item=item,
                x1=self.box.x1,
                y1=y,
                x2=self.box.x1 + dx,
                y2=y + self.key(item) / dx,
            )
            y += self.key(item) / dx

    def layoutcol(self, items: Iterable[Any]) -> Iterable[SquarifyResult]:
        covered_area = sum(self.key(item) for item in items)
        dy = covered_area / self.box.dx
        x = self.box.x1
        for item in items:
            yield SquarifyResult(
                item=item,
                x1=x,
                y1=self.box.y1,
                x2=x + self.key(item) / dy,
                y2=self.box.y1 + dy,
            )
            x += self.key(item) / dy

    def layout(self, items: Iterable[Any]) -> Iterable[SquarifyResult]:
        yield from (
            self.layoutrow(items)
            if self.box.dx >= self.box.dy
            else self.layoutcol(items)
        )

    def leftoverrow(self, items: Iterable[Any]) -> Box:
        covered_area = sum(self.key(item) for item in items)
        dx = covered_area / self.box.dy
        return Box(
            x1=self.box.x1 + dx,
            y1=self.box.y1,
            x2=self.box.x1 + self.box.dx,
            y2=self.box.y1 + self.box.dy,
        )

    def leftovercol(self, items: Iterable[Any]) -> Box:
        covered_area = sum(self.key(item) for item in items)
        dy = covered_area / self.box.dx
        return Box(
            x1=self.box.x1,
            y1=self.box.y1 + dy,
            x2=self.box.x1 + self.box.dx,
            y2=self.box.y1 + self.box.dy,
        )

    def leftover(self, items: Iterable[Any]) -> Box:
        return (
            self.leftoverrow(items)
            if self.box.dx >= self.box.dy
            else self.leftovercol(items)
        )

    def worst_ratio(self, items: Iterable[Any]) -> Decimal:
        return max(
            max(result.dx / result.dy, result.dy / result.dx)
            for result in self.layout(items)
        )

    def run(self, items: list[Any] | None = None) -> Iterable[SquarifyResult]:
        if not items:
            items = self.items

        if len(items) == 0:
            return

        if len(items) == 1:
            yield from self.layout(items)
            return

        i = 1
        while i < len(items) and self.worst_ratio(
            items[:i]
        ) >= self.worst_ratio(items[: i + 1]):
            i += 1
        current = items[:i]
        remaining = items[i:]

        leftover_box = self.leftover(current)
        yield from self.layout(current)
        yield from Squarify(
            remaining, key=self.key, box=leftover_box, normalize=False
        ).run()


def squarify(
    items: list[Any], key: Callable[[Any], Decimal], box: Box
) -> Iterable[SquarifyResult]:
    yield from Squarify(items, key, box).run()


class Shape:
    box: Box = ...

    def render(self) -> str:
        raise NotImplementedError("not implemented")


class Container(Shape):
    def __init__(self):
        self.children: list[Shape] = []

    def __post_init__(self) -> None:
        self.box = get_common_bbox(self.children)

    def render(self) -> str:
        return "\n".join(child.render() for child in self.children)


def get_common_bbox(shapes: list[Shape]) -> Box:
    return Box(
        x1=min(shape.box.x1 for shape in shapes),
        y1=min(shape.box.y1 for shape in shapes),
        x2=max(shape.box.x2 for shape in shapes),
        y2=max(shape.box.y2 for shape in shapes),
    )


@dataclass
class Rectangle(Shape):
    x: Decimal
    y: Decimal
    class_name: str
    dx: Decimal
    dy: Decimal
    title: str | None = None

    def __post_init__(self) -> None:
        self.box = Box(
            x1=self.x,
            y1=self.y,
            x2=self.x + self.dx,
            y2=self.y + self.dy,
        )

    def render(self) -> str:
        return (
            f"<rect "
            f'width="{format_decimal(max(self.dx, EPSILON))}" '
            f'height="{format_decimal(max(self.dy, EPSILON))}" '
            f'x="{format_decimal(self.x)}" '
            f'y="{format_decimal(self.y)}" '
            f'class="{self.class_name}"'
            + (f"><title>{html.escape(self.title)}</title></rect>" if self.title else "/>")
        )


class Square(Rectangle):
    def __init__(
        self,
        x: Decimal,
        y: Decimal,
        class_name: str,
        size: Decimal = GRID_SQUARE_SIZE,
        title: str | None = None,
    ) -> None:
        super().__init__(
            x=x, y=y, class_name=class_name, dx=size, dy=size, title=title
        )


@dataclass
class Text(Shape):
    x: Decimal
    y: Decimal
    text: str
    class_name: str | None = None
    size: Decimal = TEXT_SIZE
    anchor: str = "start"

    def __post_init__(self) -> None:
        self.style = ""
        if self.size != TEXT_SIZE:
            self.style = f"font-size: {self.size}px; "
        self.box = Box(x1=self.x, y1=self.y, x2=self.x, y2=self.y + self.size)

    def render(self) -> str:
        return (
            "<text "
            + (f'class="{self.class_name}" ' if self.class_name else "")
            + (f'style="{self.style}" ' if self.style else "")
            + f'text-anchor="{self.anchor}" '
            + f'x="{format_decimal(self.x)}" '
            f'y="{format_decimal(self.y + self.size/2)}">'
            f"{self.text}"
            f"</text>"
        )


class LegendText(Container):
    def __init__(self, class_name: str, text: str) -> None:
        super().__init__()
        text_shape = Text(
            x=LEGEND_SQUARE_SIZE + TEXT_MARGIN,
            y=ZERO,
            text=text,
            size=LEGEND_TEXT_SIZE,
        )

        square_shape = Square(
            x=ZERO,
            y=(text_shape.size - LEGEND_SQUARE_SIZE) / 2,
            class_name=class_name,
            size=LEGEND_SQUARE_SIZE,
        )

        self.children.extend([text_shape, square_shape])

        self.__post_init__()


@dataclass
class TranslateShape(Container):
    def __init__(
        self, children: list[Shape], x: Decimal = ZERO, y: Decimal = ZERO
    ) -> None:
        self.children = children
        self.x = x
        self.y = y

        super().__post_init__()

        self.box.x1 += self.x
        self.box.x2 += self.x
        self.box.y1 += self.y
        self.box.y2 += self.y

    def render(self) -> str:
        return (
            f'<g transform="translate({format_decimal(self.x)} {format_decimal(self.y)})">\n'
            f"{super().render()}\n"
            "</g>"
        )


@dataclass
class LegendSection(Container):
    def __init__(self, all_functions: list[Symbol]) -> None:
        super().__init__()

        captions = {
            SymbolStatus.NAMED: "Matching, named",
            SymbolStatus.DECOMPILED: "Matching, unnamed",
            SymbolStatus.NONMATCHING: "Not matching yet",
            SymbolStatus.TODO: "Not decompiled yet",
        }

        x = ZERO
        for status in SymbolStatus:
            caption = captions[status]
            legend_text = TranslateShape(
                [LegendText(class_name=status.value, text=caption)], x=x
            )
            self.children.append(legend_text)
            x += LEGEND_SQUARE_SIZE + TEXT_MARGIN + Decimal(len(caption)) * LEGEND_TEXT_SIZE / 2 + LEGEND_MARGIN * 2

        self.__post_init__()


class FunctionGrid(Container):
    def __init__(self, all_functions: list[Symbol]) -> None:
        super().__init__()
        for i, function in enumerate(all_functions):
            x = (i % GRID_MAX_SQUARES) * (
                GRID_SQUARE_SIZE + GRID_SQUARE_MARGIN
            )
            y = (i // GRID_MAX_SQUARES) * (
                GRID_SQUARE_SIZE + GRID_SQUARE_MARGIN
            )
            self.children.append(
                Square(
                    x=x,
                    y=y,
                    class_name=function.status.value,
                    title=function.signature,
                )
            )

        self.__post_init__()


class FunctionTreeGrid(Container):
    def __init__(self, all_functions: list[Symbol]) -> None:
        super().__init__()
        box = Box(
            x1=ZERO,
            y1=ZERO,
            x2=GRID_WIDTH + GRID_SQUARE_MARGIN,
            y2=(
                (
                    (len(all_functions) + GRID_MAX_SQUARES - 1)
                    // GRID_MAX_SQUARES
                )
                * (GRID_SQUARE_SIZE + GRID_SQUARE_MARGIN)
            )
            + GRID_SQUARE_MARGIN,
        )

        for result in squarify(
            [function for function in all_functions if function.size],
            key=lambda function: Decimal(function.size),
            box=box,
        ):
            result.x2 = max(ZERO, result.x2 - GRID_SQUARE_MARGIN)
            result.y2 = max(ZERO, result.y2 - GRID_SQUARE_MARGIN)

            self.children.append(
                Rectangle(
                    x=result.x1,
                    y=result.y1,
                    dx=result.dx,
                    dy=result.dy,
                    class_name=result.item.status.value,
                    title=result.item.signature,
                )
            )

        self.__post_init__()


def get_function_done_percentage(
    chosen_functions: list[Symbol],
    all_functions: list[Symbol],
    mode: SumMode,
) -> MyFraction:
    match mode:
        case SumMode.COUNT:
            return MyFraction(len(chosen_functions), len(all_functions))
        case SumMode.BYTES:
            return MyFraction(
                sum(function.size for function in chosen_functions),
                sum(function.size for function in all_functions),
            )
        case _:
            assert False


class ProgressBar(Container):
    def __init__(self, all_functions: list[Symbol], mode: SumMode) -> None:
        super().__init__()
        lx2 = ZERO

        def sorter(function):
            return list(SymbolStatus).index(function.status)

        for status_value, group in groupby(
            sorted(all_functions, key=sorter), sorter
        ):
            chosen_functions = list(group)
            if not chosen_functions:
                continue

            status = chosen_functions[0].status
            fraction = get_function_done_percentage(
                chosen_functions, all_functions, mode=mode
            )
            ratio = fraction_to_decimal(fraction)
            lx1 = lx2
            lx2 += ratio * GRID_WIDTH
            self.children.append(
                Rectangle(
                    x=lx1,
                    y=ZERO,
                    dx=lx2 - lx1,
                    dy=PROGRESS_BAR_SIZE,
                    class_name=status,
                )
            )

        self.__post_init__()


def get_functions_status_map(
    all_functions: list[Symbol],
) -> dict[SymbolStatus, list[Symbol]]:
    functions_status_map: dict[SymbolStatus, list[Symbol]] = {
        status: [] for status in SymbolStatus
    }
    for function in all_functions:
        functions_status_map[function.status].append(function)
    return functions_status_map


def get_progress_parts(
    all_functions: list[Symbol],
) -> dict[SymbolStatus, tuple[list[Symbol], dict[SumMode, MyFraction]]]:
    functions_status_map = get_functions_status_map(all_functions)

    return {
        status: (
            functions_status_map[status],
            {
                mode: get_function_done_percentage(
                    functions_status_map[status], all_functions, mode=mode
                )
                for mode in SumMode
            },
        )
        for status in SymbolStatus
    }


class GridSection(Container):
    def __init__(
        self, header: str, all_functions: list[Symbol], mode: SumMode
    ) -> None:
        super().__init__()
        header_shape = Text(x=ZERO, y=ZERO, text=header)

        y = header_shape.size + TEXT_MARGIN
        x2 = GRID_WIDTH

        progress_bar = TranslateShape(
            [ProgressBar(all_functions, mode=mode)], y=y
        )

        y = progress_bar.box.y2 + TEXT_MARGIN

        if mode == SumMode.COUNT:
            grid = TranslateShape([FunctionGrid(all_functions)], y=y)
        else:
            grid = TranslateShape([FunctionTreeGrid(all_functions)], y=y)

        progress_parts = get_progress_parts(all_functions)

        progress_text = Text(
            x=GRID_WIDTH,
            y=Decimal(3),
            size=Decimal(12),
            class_name=SymbolStatus.TODO.value,
            anchor="end",
            text=(
                " · ".join(
                    f'<tspan class="{status.value}">'
                    + f"{format_percent(progress_parts[status][1][mode])}"
                    + (
                        f" ({progress_parts[status][1][mode].numerator})"
                        if mode == SumMode.COUNT
                        else ""
                    )
                    + "</tspan>"
                    for status in SymbolStatus
                )
            ),
        )

        self.children.extend(
            [
                header_shape,
                progress_text,
                progress_bar,
                grid,
            ]
        )

        self.__post_init__()


SUMMARY_TITLES = {
    "game funcs": "Game functions",
    "game code": "Game code",
    "lib code": "Library code",
    "exe code": "Executable code",
    "exe data": "Executable data",
    "exe file": "Executable file",
}


class SummarySection(Container):
    """The terminal summary's rows as a table: the title, a bar in the
    grid's colors, the percentage and the counts behind it."""

    def __init__(self, rows: list[tuple]) -> None:
        super().__init__()
        name = project.config["game"]["exe"]
        label = Decimal(130)
        details_width = Decimal(350)
        percent_width = Decimal(50)
        details_gap = TEXT_MARGIN * 3
        bar = GRID_WIDTH - label - percent_width - details_gap - details_width
        percent = label + bar + percent_width
        y = ZERO
        for title, matched, nonmatching, whole, ratio, unit, notes in rows:
            whole = whole or 1
            x = label
            for n, status in [(matched, SymbolStatus.NAMED), (nonmatching, SymbolStatus.NONMATCHING),
                              (whole - matched - nonmatching, SymbolStatus.TODO)]:
                dx = bar * Decimal(max(n, 0)) / Decimal(whole)
                if dx > 0:
                    self.children.append(Rectangle(
                        x=x, y=y + (TEXT_SIZE - GRID_SQUARE_SIZE) / 2,
                        dx=dx, dy=GRID_SQUARE_SIZE, class_name=status.value))
                x += dx
            details = " · ".join([ratio] + [n for n in notes.split("  ") if n and n != name])
            self.children.extend([
                Text(x=ZERO, y=y, text=html.escape(SUMMARY_TITLES.get(title, title))),
                Text(x=percent, y=y, text=f'{100 * matched / whole:.1f}%', anchor="end"),
                Text(x=percent + details_gap, y=y + Decimal(1), size=Decimal(12),
                     class_name=SymbolStatus.TODO.value, text=html.escape(details)),
            ])
            y += TEXT_SIZE + Decimal(2)
        self.__post_init__()


class ProgressSVG(Container):
    def __init__(self, all_functions: list[Symbol], summary_rows: list[tuple] | None = None) -> None:
        super().__init__()

        section1 = GridSection(
            header=ORDER_HEADER,
            all_functions=all_functions,
            mode=SumMode.COUNT,
        )

        section2 = GridSection(
            header=SIZE_HEADER,
            all_functions=all_functions,
            mode=SumMode.BYTES,
        )

        legend = LegendSection(all_functions)

        header = Text(x=ZERO, y=ZERO, text=html.escape(HEADER), size=Decimal(20))
        self.children.append(header)
        top = header.box.y2 + (TEXT_MARGIN * 2 if summary_rows else SECTION_MARGIN)
        if summary_rows:
            summary_wrap = TranslateShape([SummarySection(summary_rows)], y=top)
            self.children.append(summary_wrap)
            top = summary_wrap.box.y2 + TEXT_MARGIN * 3
        section1_wrap = TranslateShape([section1], y=top)
        section2_wrap = TranslateShape(
            [section2], y=section1_wrap.box.y2 + SECTION_MARGIN
        )
        legend_wrap = TranslateShape([legend], y=section2_wrap.box.y2 + TEXT_MARGIN * 2)

        self.children.extend(
            [
                section1_wrap,
                section2_wrap,
                legend_wrap,
            ]
        )

        super().__post_init__()

    def render(self) -> str:
        x1 = -DOCUMENT_MARGIN
        y1 = -DOCUMENT_MARGIN
        x2 = self.box.dx + DOCUMENT_MARGIN * 2
        y2 = self.box.dy + DOCUMENT_MARGIN * 2
        return (
            f"""<svg version="1.1"
    width="{format_decimal(x2)}" height="{format_decimal(y2)}"
    style="display: block; margin: 0 auto"
    viewBox="{format_decimal(x1)} {format_decimal(y1)} {format_decimal(x2)} {format_decimal(y2)}"
    xmlns="http://www.w3.org/2000/svg">
    <style>
        .todo {{
            --bg: rgba(255, 255, 255, 0.25);
            --fg: rgba(100, 100, 100, 0.5);
        }}
        .decompiled {{
            --bg: rgba(255, 255, 0, 0.25);
            --fg: rgba(250, 150, 0, 0.85);
        }}
        .named {{
            --bg: rgba(0, 255, 0, 0.5);
            --fg: rgba(0, 150, 0, 0.85);
        }}
        .nonmatching {{
            --bg: rgba(255, 0, 0, 0.25);
            --fg: rgba(220, 0, 0, 0.85);
        }}
        rect {{
            fill: var(--bg);
            stroke: var(--fg);
            stroke-width: 0.5;
        }}
        text {{
            dominant-baseline: central;
            font-family: sans-serif;
            font-size: {TEXT_SIZE}px;
            fill: var(--fg, black);
            stroke: none;
        }}
        @media (prefers-color-scheme: dark) {{
          text {{
            fill: var(--fg, white);
          }}
        }}
        tspan {{
            dominant-baseline: central;
            fill: var(--fg, inherit);
        }}
    </style>
"""
            + super().render()
            + "\n</svg>"
        )


class ExeStats(TypedDict):
    code: int
    library: tuple[int, int]
    libraries: int
    unknown: int
    text: tuple[int, int]
    data: tuple[int, int]
    file: tuple[int, int]
    globals: int
    placed: int
    unmapped: int


def exe_stats() -> ExeStats | None:
    """The built exe against the original: identical bytes in .text,
    in the initialized .rdata and .data, and in the whole file; the
    library functions (after game.game_end) identical at their original
    address, the bytes no symbols.csv row covers (padding left out); and how many of
    its globals our link map lists sit at their original address. None
    when the exe or its map is not built, or for an LE game."""
    if LE:
        return None
    import compare_exe
    ours_path = os.path.join(ROOT, compare_exe.OURS)
    map_path = os.path.join(ROOT, compare_exe.MAP)
    if not (os.path.exists(ours_path) and os.path.exists(map_path)):
        return None
    ours = compare_exe.PE(ours_path)
    orig = compare_exe.PE(os.path.join(ROOT, compare_exe.ORIGINAL))

    def section(names: tuple[str, ...]) -> tuple[int, int]:
        n = t = 0
        for name in names:
            if name in ours.sections and name in orig.sections:
                va, vsize, rawptr, rawsize = ours.sections[name]
                _, vsizeb, rawptrb, rawsizeb = orig.sections[name]
                a = ours.data[rawptr:rawptr + min(vsize, rawsize)]
                b = orig.data[rawptrb:rawptrb + min(vsizeb, rawsizeb)]
                n += compare_exe.same(a, b)
                t += max(len(a), len(b))
        return n, t

    lo, vsize, _, _ = orig.sections[".text"]
    hi = lo + vsize
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        rows = list(csv.DictReader(f))
    code_rows = [(int(r["address"], 16), int(r["size"] or 0)) for r in rows if lo <= int(r["address"], 16) < hi]
    library = [(a, s) for a, s in code_rows if a >= GAME_END]
    covered = bytearray(hi - lo)
    for a, s in code_rows:
        covered[a - lo:a - lo + s] = b"\1" * min(s, hi - a)
    blob = orig.read(lo, hi - lo)
    ourmap = compare_exe.read_map(map_path)
    data_rows = [r for r in rows if orig.section_of(int(r["address"], 16)) in (".rdata", ".data")]
    hits = [next((ourmap[s][0] for s in r["symbol"].split() if s in ourmap), None) for r in data_rows]
    placed = sum(h == int(r["address"], 16) for h, r in zip(hits, data_rows))
    unmapped = hits.count(None)  # statics and folded constants the map does not list
    return {
        "code": hi - lo,
        "library": (sum(compare_exe.same(ours.read(a, s), orig.read(a, s)) for a, s in library), sum(s for a, s in library)),
        "libraries": len(library),
        "unknown": sum(1 for i, c in enumerate(covered) if not c and blob[i] not in (0x90, 0xCC, 0x00)),
        "text": section((".text",)), "data": section((".rdata", ".data")),
        "file": (compare_exe.same(ours.data, orig.data), max(len(ours.data), len(orig.data))),
        "globals": len(data_rows) - unmapped, "placed": placed, "unmapped": unmapped,
    }


def summary_rows(functions: list[Symbol], data: tuple[int, int] | None = None,
                 exe: ExeStats | None = None) -> list[tuple]:
    """One row per measure: (title, matched, nonmatching, whole,
    matched/whole as text, unit, notes). The exe rows count bytes
    identical to the original at the same position."""
    done = [f for f in functions if f.status in (SymbolStatus.NAMED, SymbolStatus.DECOMPILED)]
    red = [f for f in functions if f.status == SymbolStatus.NONMATCHING]
    total = sum(f.size for f in functions) or 1
    size = sum(f.size for f in done)
    differ = sum(f.size for f in red)
    count = len(functions) or 1

    def k(n: int) -> str:
        return f"{n / 1000:.0f}k"

    name = TITLE if LE else project.config["game"]["exe"]
    rows = [("game funcs", len(done), len(red), count, f"{len(done)}/{len(functions)}", "functions",
             (f"+{len(red)} nonmatching  " if red else "") + name),
            ("game code", size, differ, total, f"{k(size)}/{k(total)}", "bytes",
             (f"+{k(differ)} nonmatching" if red else "") + (f"  {data[0]}/{data[1]} data" if data else ""))]
    if exe:
        n, t = exe["library"]
        rows.append(("lib code", n, 0, t, f"{k(n)}/{k(t)}", "bytes", f"{exe['libraries']} functions"))
        n, t = exe["text"]
        rows.append(("exe code", n, 0, t, f"{k(n)}/{k(t)}", "bytes",
                     f"{k(exe['unknown'])} not in symbols.csv" if exe["unknown"] else ""))
        n, t = exe["data"]
        rows.append(("exe data", n, 0, t, f"{k(n)}/{k(t)}", "bytes",
                     f"{exe['placed']}/{exe['globals']} globals in place"
                     + (f"  {exe['unmapped']} not in the map" if exe["unmapped"] else "")))
        n, t = exe["file"]
        rows.append(("exe file", n, 0, t, f"{k(n)}/{k(t)}", "bytes", f"{t - n} bytes differ" if t > n else ""))
    return rows


def summary(rows: list[tuple], width: int) -> str:
    """The rows as a bar, the percentage and the counts behind it.

    Solid blocks match, shaded blocks are implemented but nonmatching,
    and light blocks remain.
    """
    widths = [max(len(r[i]) for r in rows) for i in (0, 4)]
    text = widths[0] + 2 + 8 + max(len(f"  {r[4]:>{widths[1]}} {r[5]}  {r[6]}".rstrip()) for r in rows)
    bar = max(min(40, width - 1 - text), 10)  # as wide as the terminal allows
    dim, plain = ("\033[2m", "\033[0m") if sys.stdout.isatty() else ("", "")

    def cells(n: int, whole: int) -> int:
        c = min(round(bar * n / whole), bar)
        return c - 1 if c == bar and n < whole else c  # keep a gap visible until it is all done

    lines = []
    for title, matched, nonmatching, whole, ratio, unit, notes in rows:
        whole = whole or 1
        full = cells(matched, whole)
        part = cells(matched + nonmatching, whole) - full
        lines.append(f"{title:<{widths[0]}}  " + "\u2588" * full + "\u2592" * part
                     + "\u2591" * (bar - full - part) + f"  {100 * matched / whole:5.1f}%"
                     + dim + f"  {ratio:>{widths[1]}} {unit}  {notes}".rstrip() + plain)
    return "\n".join(lines)


def main() -> None:
    import shutil

    output = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs/progress.svg")
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    if LE:
        built, data = compare_built_le()
    else:
        built, data = compare_built_pe(), None
    functions = collect_functions(built)
    rows = summary_rows(functions, data, exe_stats())
    with open(output, "w") as handle:
        print(ProgressSVG(functions, rows).render(), file=handle)
    print(summary(rows, shutil.get_terminal_size((100, 24)).columns))


if __name__ == "__main__":
    main()
