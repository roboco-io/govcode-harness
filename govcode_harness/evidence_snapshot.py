"""Bounded immutable evidence bytes; decodes and hashes share one capture."""
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import stat
from types import MappingProxyType

MAX_FILES = 1024
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 16_000_000


class SnapshotError(ValueError):
    pass


def decode(raw):
    def pairs(items):
        value = {}
        for key,item in items:
            if key in value:raise SnapshotError('EVIDENCE_INVALID')
            value[key]=item
        return value
    def invalid(_):raise SnapshotError('EVIDENCE_INVALID')
    def finite(raw):
        value=float(raw)
        if not math.isfinite(value):raise SnapshotError('EVIDENCE_INVALID')
        return value
    try:
        value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid,parse_float=finite)
        if type(value) is not dict:raise SnapshotError('EVIDENCE_INVALID')
        return value
    except (ValueError,TypeError,RecursionError):
        raise SnapshotError('EVIDENCE_INVALID') from None


@dataclass(frozen=True)
class EvidenceView:
    files: object

    def read(self,name):
        try:return decode(self.files[name])
        except KeyError:raise SnapshotError('EVIDENCE_INVALID') from None

    def raw(self,name):
        try:return self.files[name]
        except KeyError:raise SnapshotError('EVIDENCE_INVALID') from None


def capture(directory):
    """Open every component and file without following links, then retain bytes."""
    directory=Path(os.path.abspath(os.fspath(directory)))
    folder=None
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
        folder=os.open('/',flags)
        for part in directory.parts[1:]:
            child=os.open(part,flags,dir_fd=folder)
            os.close(folder);folder=child
        names=os.listdir(folder)
        if not names or len(names)>MAX_FILES:raise SnapshotError('EVIDENCE_INVALID')
        captured={};total=0
        for name in sorted(names):
            if not name.endswith('.json'):raise SnapshotError('EVIDENCE_INVALID')
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_FILE_BYTES:
                    raise SnapshotError('EVIDENCE_INVALID')
                chunks=[];size=0
                while True:
                    chunk=os.read(fd,min(65536,MAX_FILE_BYTES+1-size))
                    if not chunk:break
                    chunks.append(chunk);size+=len(chunk)
                    if size>MAX_FILE_BYTES:raise SnapshotError('EVIDENCE_INVALID')
                raw=b''.join(chunks);total+=size
                if total>MAX_TOTAL_BYTES:raise SnapshotError('EVIDENCE_INVALID')
                decode(raw)
                captured[name]=raw
            finally:os.close(fd)
        if set(os.listdir(folder))!=set(names):raise SnapshotError('EVIDENCE_INVALID')
        return EvidenceView(MappingProxyType(captured))
    except (OSError,ValueError,TypeError,RecursionError):
        raise SnapshotError('EVIDENCE_INVALID') from None
    finally:
        if folder is not None:os.close(folder)
