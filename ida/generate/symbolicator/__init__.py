import json
from typing import List
from io import TextIOWrapper


class Version(object):
    def __init__(self, max: str, min: str):
        self.max = max
        self.min = min

    def to_dict(self):
        return {"max": self.max, "min": self.min}


class Anchor(object):
    def __init__(self, string: str, segment: str, section: str, caller: str):
        self.string = string
        self.segment = segment
        self.section = section
        self.caller = caller

    def to_dict(self):
        return {"string": self.string, "segment": self.segment, "section": self.section, "caller": self.caller}


class Signature(object):
    def __init__(self, args: int, anchors: List[Anchor], symbol: str, prototype: str, caller: str):
        self.args = args
        self.anchors = anchors
        self.symbol = symbol
        self.prototype = prototype
        self.caller = caller

    def to_dict(self):
        return {
            "args": self.args,
            "anchors": [anchor.to_dict() for anchor in self.anchors],
            "symbol": self.symbol,
            "prototype": self.prototype,
            "caller": self.caller,
        }


class Symbolicator(object):
    def __init__(self, target: str, total: int, version: Version, signatures: List[Signature]):
        self.target = target
        self.total = total
        self.version = version
        self.signatures = signatures

    def to_dict(self):
        return {
            "target": self.target,
            "total": self.total,
            "version": self.version.to_dict(),
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    def write(self, file_path: str):
        with open(file_path, "w") as file:
            json.dump(self.to_dict(), file)
