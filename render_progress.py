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


CAPTIONS = {
    SymbolStatus.NAMED: "Matching, named",
    SymbolStatus.DECOMPILED: "Matching, unnamed",
    SymbolStatus.NONMATCHING: "Not matching yet",
    SymbolStatus.TODO: "Not decompiled yet",
}

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


def format_decimal(source: Decimal) -> str:
    return str(source.quantize(Decimal("1.11"))).replace(".00", "")


@dataclass
class ProgressBar:
    """Amounts of one measure by status, in the order they are drawn."""

    sections: dict[str, float | int]

    @property
    def total(self) -> float | int:
        return sum(self.sections.values())

    def ratio(self, *keys: str) -> Decimal:
        return Decimal(sum(self.sections.get(k, 0) for k in keys)) / Decimal(self.total or 1)

    @property
    def matched(self) -> Decimal:
        return self.ratio(SymbolStatus.NAMED, SymbolStatus.DECOMPILED)


def by_status(functions: list[Symbol], mode: "SumMode") -> ProgressBar:
    return ProgressBar({
        status: sum(f.size if mode == SumMode.BYTES else 1 for f in functions if f.status == status)
        for status in SymbolStatus
    })


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

        x = ZERO
        for status in SymbolStatus:
            caption = CAPTIONS[status]
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


def gutter_scale(sizes: list[Decimal], box: Box) -> Decimal:
    """The t that has squares of side t * sqrt(size), each with a gutter
    added to its side, fill `box`: the quadratic sum((t * sqrt(size) +
    GRID_SQUARE_MARGIN) ** 2) = area, solved for t."""
    g = GRID_SQUARE_MARGIN
    a = sum(sizes)
    b = 2 * g * sum(size.sqrt() for size in sizes)
    c = len(sizes) * g * g - box.dx * box.dy
    return (-b + (b * b - 4 * a * c).sqrt()) / (2 * a)


def trim(side: Decimal) -> Decimal:
    """A slot's side less its gutter. A slot too thin for one (squarify
    gives the last, smallest functions skinny slots) keeps a 1px cell,
    still in its place."""
    return min(side, max(side - GRID_SQUARE_MARGIN, Decimal(1)))


class FunctionTreeGrid(Container):
    """The functions as a treemap. Each cell's slot holds its area and a
    gutter, so the cells keep their areas apart from one even gutter."""

    def __init__(self, all_functions: list[Symbol]) -> None:
        super().__init__()
        rows = (len(all_functions) + GRID_MAX_SQUARES - 1) // GRID_MAX_SQUARES
        # The slots on the right and bottom edges keep their gutters
        # outside the grid.
        box = Box(
            x1=ZERO,
            y1=ZERO,
            x2=GRID_WIDTH + GRID_SQUARE_MARGIN,
            y2=rows * (GRID_SQUARE_SIZE + GRID_SQUARE_MARGIN),
        )
        functions = [function for function in all_functions if function.size]
        t = gutter_scale([Decimal(function.size) for function in functions], box)

        for result in squarify(
            functions,
            key=lambda function: (t * Decimal(function.size).sqrt() + GRID_SQUARE_MARGIN) ** 2,
            box=box,
        ):
            # A 1px cell on the edge moves into its own gutter to stay
            # in the grid.
            dx, dy = trim(result.dx), trim(result.dy)
            self.children.append(
                Rectangle(
                    x=min(result.x1, box.x2 - GRID_SQUARE_MARGIN - dx),
                    y=min(result.y1, box.y2 - GRID_SQUARE_MARGIN - dy),
                    dx=dx,
                    dy=dy,
                    class_name=result.item.status.value,
                    title=result.item.signature,
                )
            )

        self.__post_init__()


class ProgressBarShape(Container):
    def __init__(self, progress: ProgressBar, width: Decimal, height: Decimal,
                 titles: dict[str, str] | None = None) -> None:
        super().__init__()
        x2 = ZERO
        for key, amount in progress.sections.items():
            if not amount:
                continue
            x1 = x2
            x2 += progress.ratio(key) * width
            self.children.append(Rectangle(x=x1, y=ZERO, dx=x2 - x1, dy=height, class_name=key,
                                           title=(titles or {}).get(key)))
        self.__post_init__()


class GridSection(Container):
    """A header over the functions as squares (COUNT) or a treemap
    (BYTES). Their bar and amounts are the summary's Game functions or
    Game code row."""

    def __init__(
        self, header: str, all_functions: list[Symbol], mode: SumMode
    ) -> None:
        super().__init__()
        header_shape = Text(x=ZERO, y=ZERO, text=header)

        y = header_shape.size + TEXT_MARGIN

        if mode == SumMode.COUNT:
            grid = TranslateShape([FunctionGrid(all_functions)], y=y)
        else:
            grid = TranslateShape([FunctionTreeGrid(all_functions)], y=y)

        self.children.extend([header_shape, grid])

        self.__post_init__()


@dataclass
class SummaryRow:
    title: str
    progress: ProgressBar
    notes: list[str]
    unit: Callable[[float | int], str] = str  # writes an amount

    @property
    def amounts(self) -> list[tuple[str, str]]:
        """Each section that has any, with its amount written out."""
        return [(key, self.unit(n)) for key, n in self.progress.sections.items() if n]


class SummarySection(Container):
    """The terminal summary's rows as a table: the title, a bar in the
    grid's colors, the percentage, the amounts in their colors and the
    notes."""

    def __init__(self, rows: list[SummaryRow]) -> None:
        super().__init__()
        label = Decimal(130)
        details_width = Decimal(350)
        percent_width = Decimal(50)
        details_gap = TEXT_MARGIN * 3
        bar = GRID_WIDTH - label - percent_width - details_gap - details_width
        percent = label + bar + percent_width
        y = ZERO
        for row in rows:
            self.children.extend([
                Text(x=ZERO, y=y, text=html.escape(row.title)),
                TranslateShape([ProgressBarShape(row.progress, bar, GRID_SQUARE_SIZE, {
                    key: f"{n} · {format_decimal(row.progress.ratio(key) * 100)}%" for key, n in row.amounts
                })],
                               x=label, y=y + (TEXT_SIZE - GRID_SQUARE_SIZE) / 2),
                Text(x=percent, y=y, text=f"{100 * row.progress.matched:.1f}%", anchor="end"),
                Text(x=percent + details_gap, y=y + Decimal(1), size=Decimal(12),
                     class_name=SymbolStatus.TODO.value,
                     text=" · ".join([f'<tspan class="{key}">{html.escape(n)}</tspan>' for key, n in row.amounts]
                                     + [html.escape(note) for note in row.notes])),
            ])
            y += TEXT_SIZE + Decimal(2)
        self.__post_init__()


class ProgressSVG(Container):
    def __init__(self, all_functions: list[Symbol], summary_rows: list[SummaryRow] | None = None) -> None:
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
                 exe: ExeStats | None = None) -> list[SummaryRow]:
    """One row per measure. The exe rows count bytes identical to the
    original at the same position."""

    def kb(n: float | int) -> str:
        return f"{n / 1000:.0f} KB" if n >= 500 else f"{n} bytes"

    def exe_row(title: str, same: int, whole: int, notes: list[str]) -> SummaryRow:
        bar = ProgressBar({SymbolStatus.NAMED: same, SymbolStatus.TODO: whole - same})
        return SummaryRow(title, bar, notes, kb)

    rows = [
        SummaryRow("Game functions", by_status(functions, SumMode.COUNT), []),
        SummaryRow("Game code", by_status(functions, SumMode.BYTES),
                   [f"{data[0]}/{data[1]} data segments"] if data else [], kb),
    ]
    if exe:
        rows += [
            exe_row("Library code", *exe["library"], [f"{exe['libraries']} functions"]),
            exe_row("Executable code", *exe["text"],
                    [f"{kb(exe['unknown'])} not in symbols.csv"] if exe["unknown"] else []),
            exe_row("Executable data", *exe["data"],
                    [f"{exe['placed']}/{exe['globals']} globals in place"]
                    + ([f"{exe['unmapped']} not in the map"] if exe["unmapped"] else [])),
            exe_row("Executable file", *exe["file"], []),
        ]
    return rows


# Each status its own block, so the bar reads in plain text.
BLOCKS = {SymbolStatus.NAMED: "\u2588", SymbolStatus.DECOMPILED: "\u2593",
          SymbolStatus.NONMATCHING: "\u2592", SymbolStatus.TODO: "\u2591"}


def cells(progress: ProgressBar, bar: int) -> dict[str, int]:
    """How many of `bar` cells each section takes: its share, rounded by
    the largest remainders, and at least one for a section that has
    any, taken from the largest."""
    ideal = {key: progress.ratio(key) * bar for key, n in progress.sections.items() if n}
    out = {key: max(int(x), 1) for key, x in ideal.items()}
    while sum(out.values()) < bar:
        key = max(ideal, key=lambda k: ideal[k] - out[k])
        out[key] += 1
    while sum(out.values()) > bar:
        key = max(out, key=lambda k: out[k])
        out[key] -= 1
    return out


def summary(rows: list[SummaryRow], width: int) -> str:
    """The image's header, then the rows as a bar, the percentage, the
    amounts and the notes, each status in its own block, then a legend
    of the blocks. Plain text, so it pastes as it shows."""

    def details(r: SummaryRow) -> str:
        return "  ".join([f"{BLOCKS[key]} {n}" for key, n in r.amounts] + r.notes)

    title_width = max(len(r.title) for r in rows)
    text = title_width + 2 + 8 + 2 + max(len(details(r)) for r in rows)
    bar = max(min(40, width - 1 - text), 20)  # as wide as the terminal allows

    lines = [HEADER, ""]
    for r in rows:
        drawn = "".join(BLOCKS[key] * n for key, n in cells(r.progress, bar).items())
        lines.append(f"{r.title:<{title_width}}  {drawn}  {100 * r.progress.matched:5.1f}%  {details(r)}")
    lines.append("")
    lines.append("  ".join(f"{BLOCKS[status]} {CAPTIONS[status]}" for status in SymbolStatus))
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
