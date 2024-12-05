from enum import Enum
from typing import List
from dataclasses import dataclass


class EditStatus(Enum):
    EQL = "eql"
    INS = "ins"
    DEL = "del"


SYMBOLS: dict[EditStatus, str] = {
    EditStatus.EQL: " ",
    EditStatus.INS: "+",
    EditStatus.DEL: "-",
}

NULL_PATH = "/dev/null"

HUNK_CONTEXT = 3


@dataclass
class Line:
    line_number: int
    text: str


@dataclass
class Edit:
    """
    Data class to represent a line of diff.
    """

    edit_type: EditStatus
    a_line: Line | None
    b_line: Line | None

    def to_str(self) -> str:
        line = self.a_line or self.b_line
        return SYMBOLS.get(self.edit_type, "") + line.text if line is not None else ""


@dataclass
class Hunk:
    a_start: int
    b_start: int
    edits: List[Edit]

    def __init__(self, a_start: int, b_start: int, edits: List[Edit]) -> None:
        self.a_start = a_start
        self.b_start = b_start
        self.edits = edits

    @staticmethod
    def filter(edits: List[Edit]):
        hunks = []
        offset: int = 0
        edits_len = len(edits)

        while True:
            while offset < edits_len and edits[offset].edit_type == EditStatus.EQL:
                offset += 1

            if offset >= edits_len:
                return hunks

            # go back (HUNK_CONTEXT + 1) lines of context
            offset -= HUNK_CONTEXT + 1
            a_start = (
                0
                if offset < 0 or edits[offset].a_line is None
                else edits[offset].a_line.line_number
            )
            b_start = (
                0
                if offset < 0 or edits[offset].b_line is None
                else edits[offset].b_line.line_number
            )

            hunks.append(Hunk(a_start, b_start, []))
            offset = Hunk.build(hunks[-1], edits, offset)

    @staticmethod
    def build(hunk: "Hunk", edits: List[Edit], offset: int):
        # the `"Hunk"` type hint is **forward reference**
        """
        Add edits to the hunk until there are no more changes that are close to the last one we collected.
        """

        # how many edits are left to add to the hunk
        counter = -1
        # counter == 0 is when we run out of edits
        while counter != 0:
            # making sure we are not pointing at the empty space before the start of the edits array,
            # and we are not on the first turn of the loop - we do _not_ want to collect
            # the first edit as it's the one _before_ where we want the hunk to start
            if offset >= 0 and counter > 0:
                # add the current edit to the hunk
                # keep adding the current Edit to the hunk (even though there is no change)
                # until we reach the further edge of the context, because we need to
                # make sure to include `HUNK_CONTEXT` lines of unchanged lines
                hunk.edits.append(edits[offset])

            offset += 1
            if offset >= len(edits):
                break

            # offset is where the context begins, _NOT_ where the changes begin
            # the closest change might be (offset + HUNK_CONTEXT) away
            if offset + HUNK_CONTEXT < len(edits):
                match edits[offset + HUNK_CONTEXT].edit_type:
                    case EditStatus.INS:
                        counter = 2 * HUNK_CONTEXT + 1
                    case EditStatus.DEL:
                        counter = 2 * HUNK_CONTEXT + 1
                    case _:
                        counter -= 1

        return offset

    def header(self):
        """
        Produce the `@@` line at the beginning of each hunk.
        """

        a_lines = [
            edit.a_line for edit in self.edits if edit and edit.a_line is not None
        ]
        a_lines_start = a_lines[0].line_number if len(a_lines) > 0 else self.a_start
        b_lines = [
            edit.b_line for edit in self.edits if edit and edit.b_line is not None
        ]
        b_lines_start = b_lines[0].line_number if len(b_lines) > 0 else self.b_start

        a_offset = ",".join(str(x) for x in [a_lines_start, len(a_lines)])
        b_offset = ",".join(str(x) for x in [b_lines_start, len(b_lines)])

        return f"@@ -{a_offset} +{b_offset} @@"


def lines(text: str | List[str]) -> List[Line]:
    document: List[str] = text.splitlines() if isinstance(text, str) else text
    return [Line(index + 1, line) for index, line in enumerate(document)]


def diff(a: str | List[str], b: str | List[str]):
    return Diff.diff(lines(a), lines(b))


def diff_hunks(a: str, b: str):
    return Hunk.filter(diff(a, b))


class Diff:
    def __init__(self, a: List[Line], b: List[Line]) -> None:
        self.a = a
        self.b = b

    @staticmethod
    def diff(a: List[Line], b: List[Line]):
        dd = Diff(a, b)
        return dd.diff_impl(a, b)

    def diff_impl(self, a: List[Line], b: List[Line]) -> List[Edit]:
        diffs: List[Edit] = []
        for prev_x, prev_y, x, y in self.backtrack():
            a_line = self.a[prev_x % len(self.a)]
            b_line = self.b[prev_y % len(self.b)]

            if x == prev_x:
                diffs.append(Edit(EditStatus.INS, None, b_line))
            elif y == prev_y:
                diffs.append(Edit(EditStatus.DEL, a_line, None))
            else:
                diffs.append(Edit(EditStatus.EQL, a_line, b_line))

        return list(reversed(diffs))

    def ses(self) -> list[list]:
        """
        Find **shortest edit script**
        """
        a_len = len(self.a)
        b_len = len(self.b)
        max_len = a_len + b_len

        # set up an array to store the latest value of `x` for each `k`
        # `k` can take values from `-max_len` to `max_len`
        arr = [0] * (2 * max_len + 1)
        traces = list()

        # whether to move downward/rightward from the _previous_ round
        for d in range(0, max_len + 1):
            traces.append(arr[:])
            for k in range(-d, d + 1, 2):
                # calculate x arr[k]
                if k == -d or (k != d and arr[k - 1] < arr[k + 1]):
                    # move downward
                    # x value is equal to the k+1 x-value in the previous round
                    # go downward _from_ `arr[k + 1]` - we want the higher x value
                    # this might not be the final position/value because of diagonals
                    x = arr[k + 1]
                else:
                    # move rightwards - x incremented by 1
                    x = arr[k - 1] + 1

                y = x - k

                while x < a_len and y < b_len and self.a[x].text == self.b[y].text:
                    x += 1
                    y += 1

                # update the _current_ x
                arr[k] = x

                # return the current value of `d` if reached bottom-right
                if x >= a_len and y >= b_len:
                    return traces

    def backtrack(self):
        # x and y here are the final values/positions,
        # that we want to backtrack from
        x = len(self.a)
        y = len(self.b)

        traces = self.ses()
        for d, arr in reversed(list(enumerate(traces))):
            # calculate k
            k = x - y

            if k == -d or (k != d and arr[k - 1] < arr[k + 1]):
                prev_k = k + 1
            else:
                prev_k = k - 1

            prev_x = arr[prev_k]
            prev_y = prev_x - prev_k

            while x > prev_x and y > prev_y:
                # if current x and y are both greater than previous,
                # we can move diagonally
                yield (x - 1, y - 1, x, y)
                x -= 1
                y -= 1

            if d > 0:
                yield (prev_x, prev_y, x, y)

            x = prev_x
            y = prev_y


@dataclass
class DiffTarget:
    """
    A target class to compare/print two diffs
    """

    path: str
    sha: str
    mode: str | None
    data: str

    def diff_path(self):
        return self.path if self.mode is not None else NULL_PATH

    def set_path(self, path_new: str):
        self.path = path_new


def main():
    a = "ABCABBA"
    b = "CBABAC"

    edits = diff([*a], [*b])
    for edit in edits:
        print(edit.to_str())
