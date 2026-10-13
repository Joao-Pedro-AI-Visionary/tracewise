#!/usr/bin/env python3
"""Stand-in for Hopper's launcher and embedded Python API.

REA and tracewise start Hopper as `<launcher> [loader args] --analysis -Y <bootstrap.py>
--executable <path>`; the bootstrap executes the packaged `hopper_bridge.py` inside Hopper's
interpreter, where the `Document` class is a global. This launcher provides that global,
backed by sample_model.json (derived from fixtures/engines/sample_elf), then executes the
bootstrap unchanged. Only the API surface the bridge uses is emulated; analysis is "complete".
"""
import json
import os
import sys

# FAKE_HOPPER_DROP_WRITES=1 makes every mutating call report success without persisting it, so the
# bridge's mandatory read-back sees stale state (the negative path of the annotation tools).
DROP_WRITES = os.environ.get("FAKE_HOPPER_DROP_WRITES") == "1"

HERE = os.path.dirname(os.path.abspath(__file__))
BAD = 0xFFFFFFFFFFFFFFFF


class CallReference:
    def __init__(self, source, target, kind=2):
        self._source, self._target, self._kind = source, target, kind

    def fromAddress(self):
        return self._source

    def toAddress(self):
        return self._target

    def type(self):
        return self._kind


class Local:
    def __init__(self, record):
        self._record = record

    def name(self):
        return self._record["name"]

    def displacement(self):
        return self._record["displacement"]


class Instruction:
    def __init__(self, record):
        self._record = record

    def getInstructionLength(self):
        return self._record["length"]

    def getInstructionString(self):
        return self._record["mnemonic"]

    def getArgumentCount(self):
        return len(self._record["args"])

    def getFormattedArgument(self, index):
        return self._record["args"][index]


class BasicBlock:
    def __init__(self, record):
        self._record = record

    def getStartingAddress(self):
        return self._record["start"]

    def getEndingAddress(self):
        # Hopper 6.1 reports the final instruction's address.
        return self._record["end"]

    def getSuccessorCount(self):
        return len(self._record["successors"])

    def getSuccessorAddressAtIndex(self, index):
        return self._record["successors"][index]


class Procedure:
    def __init__(self, document, segment, record):
        self._document, self._segment, self._record = document, segment, record
        self._blocks = [BasicBlock(b) for b in record["blocks"]]
        self._instruction_blocks = {}
        for block in self._blocks:
            start = block.getStartingAddress()
            for ins in record["instructions"]:
                if ins["address"] >= start and ins["address"] <= block.getEndingAddress():
                    self._instruction_blocks[ins["address"]] = block

    def getEntryPoint(self):
        return self._record["entry"]

    def getSegment(self):
        return self._segment

    def basicBlockIterator(self):
        return list(self._blocks)

    def getBasicBlockCount(self):
        return len(self._blocks)

    def getBasicBlockAtAddress(self, address):
        return self._instruction_blocks.get(address)

    def _calls(self):
        out = []
        for ins in self._record["instructions"]:
            if ins["mnemonic"].startswith("call"):
                for target in ins["refs"]:
                    out.append(CallReference(ins["address"], target))
        return out

    def getAllCallees(self):
        return self._calls()

    def getAllCallers(self):
        entry = self._record["entry"]
        out = []
        for other in self._document._procedures:
            if other is self:
                continue
            for call in other._calls():
                if call.toAddress() == entry:
                    out.append(call)
        return out

    def getAllCalleeProcedures(self):
        seen, out = set(), []
        for call in self._calls():
            procedure = self._document._procedure_by_entry.get(call.toAddress())
            if procedure is not None and procedure.getEntryPoint() not in seen:
                seen.add(procedure.getEntryPoint())
                out.append(procedure)
        return out

    def getAllCallerProcedures(self):
        seen, out = set(), []
        entry = self._record["entry"]
        for other in self._document._procedures:
            if other is self:
                continue
            if any(call.toAddress() == entry for call in other._calls()) and other.getEntryPoint() not in seen:
                seen.add(other.getEntryPoint())
                out.append(other)
        return out

    def signatureString(self):
        return self._record["signature"]

    def getLocalVariableList(self):
        return [Local(item) for item in self._record["locals"]]

    def decompile(self):
        return self._record["pseudocode"]


class Section:
    def __init__(self, record):
        self._record = record

    def getName(self):
        return self._record["name"]

    def getStartingAddress(self):
        return self._record["start"]

    def getLength(self):
        return self._record["length"]


class Segment:
    TYPE_UNDEFINED = 0
    TYPE_ASCII = 3
    TYPE_UNICODE = 4

    def __init__(self, document, record):
        self._document, self._record = document, record
        self._bytes = bytearray(bytes.fromhex(record["bytes_hex"]))
        self._start, self._length = record["start"], record["length"]
        self._procedures = []
        self._instructions = {}
        self._comments, self._inline_comments = {}, {}

    def getName(self):
        return self._record["name"]

    def getStartingAddress(self):
        return self._start

    def getLength(self):
        return self._length

    def getSectionsList(self):
        return [Section(item) for item in self._record["sections"]]

    def getProcedureCount(self):
        return len(self._procedures)

    def getProcedureAtIndex(self, index):
        return self._procedures[index]

    def getProcedureAtAddress(self, address):
        for procedure in self._procedures:
            if address in procedure._instruction_blocks or any(
                ins["address"] <= address < ins["address"] + ins["length"] for ins in procedure._record["instructions"]
            ):
                return procedure
        return None

    def getNameAtAddress(self, address):
        return self._document._names.get(address)

    def getNamedAddresses(self):
        return sorted(a for a in self._document._names if self._start <= a < self._start + self._length)

    def getCommentAtAddress(self, address):
        return self._comments.get(address)

    def getInlineCommentAtAddress(self, address):
        return self._inline_comments.get(address)

    def setCommentAtAddress(self, address, text):
        if DROP_WRITES:
            return
        if text:
            self._comments[address] = text
        else:
            self._comments.pop(address, None)

    def setInlineCommentAtAddress(self, address, text):
        if DROP_WRITES:
            return
        if text:
            self._inline_comments[address] = text
        else:
            self._inline_comments.pop(address, None)

    def getReferencesFromAddress(self, address):
        ins = self._document._instruction_records.get(address)
        return list(ins["refs"]) if ins else []

    def getReferencesOfAddress(self, address):
        return sorted(self._document._reverse_refs.get(address, []))

    def getInstructionAtAddress(self, address):
        record = self._document._instruction_records.get(address)
        return Instruction(record) if record and self._start <= address < self._start + self._length else None

    def getInstructionStart(self, address):
        for start, record in self._document._instruction_records.items():
            if start <= address < start + record["length"] and self._start <= address < self._start + self._length:
                return start
        for item in self._document._strings:
            if item["address"] <= address < item["address"] + item["length"]:
                return item["address"]
        return BAD

    def getObjectLength(self, address):
        record = self._document._instruction_records.get(address)
        if record:
            return record["length"]
        for item in self._document._strings:
            if item["address"] == address:
                return item["length"]
        return 1

    def getStringsList(self):
        return [
            (item["display"], item["address"])
            for item in self._document._strings
            if self._start <= item["address"] < self._start + self._length
        ]

    def getTypeAtAddress(self, address):
        for item in self._document._strings:
            if item["address"] == address:
                return Segment.TYPE_ASCII
        return Segment.TYPE_UNDEFINED

    def readBytes(self, address, length):
        offset = address - self._start
        if offset < 0 or offset + length > self._length:
            return False
        return bytes(self._bytes[offset : offset + length])


class FakeDocument:
    def __init__(self, model, executable_path):
        self._model = model
        self._executable_path = executable_path
        self._names = {int(k): v for k, v in model["names"].items()}
        self._strings = model["strings"]
        self._cursor = model["procedures"][0]["entry"] if model["procedures"] else 0
        self._bookmarks = {}
        self._closed = False
        self._segments = [Segment(self, record) for record in model["segments"]]
        self._procedures = []
        self._procedure_by_entry = {}
        self._instruction_records = {}
        self._reverse_refs = {}
        for record in model["procedures"]:
            segment = self._segment_containing(record["entry"])
            procedure = Procedure(self, segment, record)
            segment._procedures.append(procedure)
            self._procedures.append(procedure)
            self._procedure_by_entry[record["entry"]] = procedure
            for ins in record["instructions"]:
                self._instruction_records[ins["address"]] = ins
                for target in ins["refs"]:
                    self._reverse_refs.setdefault(target, []).append(ins["address"])
        for segment in self._segments:
            segment._procedures.sort(key=lambda p: p.getEntryPoint())

    def _segment_containing(self, address):
        for segment in self._segments:
            if segment.getStartingAddress() <= address < segment.getStartingAddress() + segment.getLength():
                return segment
        raise KeyError(address)

    def getDocumentName(self):
        return os.path.basename(self._executable_path)

    def getExecutableFilePath(self):
        return self._executable_path

    def getDatabaseFilePath(self):
        return None

    def backgroundProcessActive(self):
        return False

    def requestBackgroundProcessStop(self):
        pass

    def waitForBackgroundProcessToEnd(self):
        pass

    def closeDocument(self):
        self._closed = True

    def getCurrentAddress(self):
        return self._cursor

    def moveCursorAtAddress(self, address):
        segment = self.getSegmentAtAddress(address)
        if segment is None:
            return
        start = segment.getInstructionStart(address)
        self._cursor = address if start == BAD else start

    def getSegmentAtAddress(self, address):
        for segment in self._segments:
            if segment.getStartingAddress() <= address < segment.getStartingAddress() + segment.getLength():
                return segment
        return None

    def getSegmentsList(self):
        return list(self._segments)

    def getAddressForName(self, name):
        for address, candidate in self._names.items():
            if candidate == name:
                return address
        return BAD

    def readBytes(self, address, length):
        segment = self.getSegmentAtAddress(address)
        return segment.readBytes(address, length) if segment is not None else False

    def getFileOffsetFromAddress(self, address):
        for load in self._model["file_offsets"]:
            if load["vaddr"] <= address < load["vaddr"] + load["filesz"]:
                return load["offset"] + address - load["vaddr"]
        return BAD

    def getAddressFromFileOffset(self, offset):
        for load in self._model["file_offsets"]:
            if load["offset"] <= offset < load["offset"] + load["filesz"]:
                return load["vaddr"] + offset - load["offset"]
        return BAD

    def setNameAtAddress(self, address, name):
        if DROP_WRITES:
            return True
        if self.getSegmentAtAddress(address) is None:
            return False
        if name:
            self._names[address] = name
        else:
            self._names.pop(address, None)
        return True

    def getBookmarks(self):
        return sorted(self._bookmarks)

    def getBookmarkName(self, address):
        return self._bookmarks.get(address)

    def setBookmarkAtAddress(self, address, name):
        if DROP_WRITES:
            return
        self._bookmarks[address] = name

    def hasBookmarkAtAddress(self, address):
        return address in self._bookmarks

    def removeBookmarkAtAddress(self, address):
        if DROP_WRITES:
            return
        self._bookmarks.pop(address, None)


def main(argv):
    if "-Y" not in argv or ("--executable" not in argv and "--database" not in argv):
        sys.stderr.write("fake Hopper: expected --analysis -Y <bootstrap> --executable <path>\n")
        return 64
    bootstrap = argv[argv.index("-Y") + 1]
    flag = "--executable" if "--executable" in argv else "--database"
    target = argv[argv.index(flag) + 1]
    with open(os.environ.get("FAKE_HOPPER_MODEL", os.path.join(HERE, "sample_model.json"))) as handle:
        model = json.load(handle)
    document = FakeDocument(model, target)

    class DocumentProvider:
        @classmethod
        def getAllDocuments(cls):
            return [] if document._closed else [document]

        @classmethod
        def getCurrentDocument(cls):
            return None if document._closed else document

    environment = {"__name__": "__main__", "Document": DocumentProvider}
    with open(bootstrap, "rb") as handle:
        source = handle.read()
    exec(compile(source, bootstrap, "exec"), environment)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
