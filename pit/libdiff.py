from typing import List
from dataclasses import dataclass

SYMBOLS: dict[str, str] = {
    "eql": " ",
    "ins": "+",
    "del": "-",
}

NULL_PATH = "/dev/null"


def diff(a: str | List[str], b: str | List[str]):
    return Diff.diff([*a] if type(a) is str else a, [*b] if type(b) is str else b)


@dataclass
class Edit:
    """
    Data class to represent a line of diff.
    """

    edit_type: str
    text: str

    def to_str(self) -> str:
        return SYMBOLS.get(self.edit_type, "") + self.text


class Diff:
    def __init__(self, a: List[str], b: List[str]) -> None:
        self.a = a
        self.b = b

    @staticmethod
    def diff(a: List[str], b: List[str]):
        dd = Diff(a, b)
        return dd.diff_impl(a, b)

    def diff_impl(self, a: List[str], b: List[str]):
        diffs = []
        for prev_x, prev_y, x, y in self.backtrack():
            a_line = self.a[prev_x % len(self.a)]
            b_line = self.b[prev_y % len(self.b)]

            if x == prev_x:
                diffs.append(Edit("ins", b_line))
            elif y == prev_y:
                diffs.append(Edit("del", a_line))
            else:
                diffs.append(Edit("eql", a_line))

        return reversed(diffs)

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

                while x < a_len and y < b_len and self.a[x] == self.b[y]:
                    x += 1
                    y += 1

                # update the _current_ x
                arr[k] = x

                # return the current value of `d` if reached bottom-right
                if x >= a_len and y >= b_len:
                    return traces
                    # return d

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

    def diff_path(self):
        return self.path if self.mode is not None else NULL_PATH

    def set_path(self, path_new: str):
        self.path = path_new


def main():
    a = "ABCABBA"
    b = "CBABAC"

    edits = diff(a, b)
    for edit in edits:
        print(edit.to_str())
