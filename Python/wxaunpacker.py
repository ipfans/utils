"""Unpacker for wechat wxa hybird app."""

import sys
from pathlib import Path
from struct import unpack

if sys.version_info.major < 3 and sys.version_info.minor < 6:
    RuntimeError("This script should work with Python 3.6+")


class WxaUnpacker(object):

    def __init__(self, data):
        super(WxaUnpacker, self).__init__()
        self._data = data

    def is_valid(self):
        if self._data[:5] != b'\xBE\x00\x00\x00\x00':
            return False
        return True

    def get_file_list(self):
        offset_size = unpack('>i', self._data[5:9])[0]
        file_list = self._data[18:18+offset_size]
        i = 0
        while (i < offset_size-4):
            fn_size = unpack('>i', file_list[i:i+4])[0]
            fn = file_list[i+4:i+4+fn_size].decode('utf-8')
            if fn[0] == '/':
                fn = fn[1:]
            start = unpack('>i', file_list[i+4+fn_size:i+8+fn_size])[0]
            size = unpack('>i', file_list[i+8+fn_size:i+12+fn_size])[0]
            yield (fn, start, size)
            i = i+12+fn_size

    def extract_data(self, start, size):
        return self._data[start:start+size]


def mkpath(path):
    if path.exists():
        return
    if path.parent.exists():
        path.mkdir()
    else:
        mkpath(path.parent)
        path.mkdir()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"{sys.argv[0]} 12345.wxapkg")
        exit(0)
    fp = Path(sys.argv[1])
    if not fp.exists() or fp.is_dir():
        print(f"file {sys.argv[1]} not found.")
        exit(-1)
    newfp = Path(''.join(fp.name.split('.')[:-1])).absolute()
    if newfp.exists():
        print(f"path {newfp} found.")
        exit(-1)
    newfp.mkdir()
    with fp.open(mode='rb') as f:
        unpacker = WxaUnpacker(f.read())
        if not unpacker.is_valid():
            print(f"file {sys.argv[1]} maybe not a wxapkg file.")
            exit(-1)
        for fn, offset, size in unpacker.get_file_list():
            write_file = newfp.absolute().joinpath(fn)
            mkpath(write_file.parent)
            with Path(write_file).open(mode='wb') as wfp:
                wfp.write(unpacker.extract_data(offset, size))
