"""Atomic fixture-file replacement; footprint spec section 3.2 owns this boundary.

Callers own ordinary files and their real parent/ancestors in a private temporary
tree. This is not protection against a process racing those paths.
"""
import ctypes
import ntpath
import os
import stat
import sys

MAX_NAME_UNITS = 32766
MAX_BUFFER_BYTES = 65560
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _RenameFlags(ctypes.Union):
    _fields_ = [('Flags', ctypes.c_uint32), ('ReplaceIfExists', ctypes.c_uint8)]


class _RenameInfo(ctypes.Structure):
    _anonymous_ = ('control',)
    _fields_ = [('control', _RenameFlags), ('RootDirectory', ctypes.c_void_p),
                ('FileNameLength', ctypes.c_uint32), ('FileName', ctypes.c_uint16 * 1)]


def _require_layout():
    if (ctypes.sizeof(ctypes.c_void_p), ctypes.alignment(_RenameInfo), ctypes.sizeof(_RenameInfo),
            _RenameInfo.Flags.offset, _RenameInfo.RootDirectory.offset,
            _RenameInfo.FileNameLength.offset, _RenameInfo.FileName.offset) != (8, 8, 24, 0, 8, 16, 20):
        raise ValueError('fixture rename requires the reviewed Windows x64 layout')


def _encode_name(path, max_units):
    if type(max_units) is not int or not 0 < max_units <= MAX_NAME_UNITS:
        raise ValueError('invalid fixture name bound')
    if not isinstance(path, str) or not path or '\0' in path or len(path) > max_units:
        raise ValueError('invalid fixture name')
    units = 0
    for character in path:
        value = ord(character)
        if 0xD800 <= value <= 0xDFFF:
            raise ValueError('unpaired surrogate in fixture name')
        units += 1 if value <= 0xFFFF else 2
        if units > max_units:
            raise ValueError('fixture name exceeds UTF-16 bound')
    return path.encode('utf-16-le', errors='strict')


def _rename_buffer(destination, *, max_units=MAX_NAME_UNITS):
    _require_layout()
    encoded = _encode_name(destination, max_units)
    size = (20 + len(encoded) + 2 + 7) // 8 * 8
    if not 24 <= size <= MAX_BUFFER_BYTES or size > 0xFFFFFFFF:
        raise ValueError('fixture rename buffer exceeds its checked bound')
    storage = (ctypes.c_uint64 * (size // 8))()
    if ctypes.addressof(storage) % 8:
        raise ValueError('unaligned fixture rename buffer')
    header = _RenameInfo.from_buffer(storage)
    header.Flags, header.RootDirectory, header.FileNameLength = 3, None, len(encoded)
    ctypes.memmove(ctypes.addressof(storage) + 20, encoded, len(encoded))
    return storage


def _absolute_file(path):
    path = os.fspath(path)
    _encode_name(path, MAX_NAME_UNITS)
    drive, tail = ntpath.splitdrive(path)
    if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha() or drive[1] != ':'
            or not tail.startswith(('\\', '/')) or tail.endswith(('\\', '/'))
            or ':' in tail or ntpath.isreserved(path)):
        raise ValueError('fixture path must name an ordinary absolute Windows file')
    return ntpath.normpath(path)


def _ordinary(path, *, directory=False):
    info = os.lstat(path)
    if (getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('fixture path is a directory, reparse point or nonordinary file')


class _WindowsAPI:
    def __init__(self, kernel, last_error, error):
        self.CreateFileW = kernel.CreateFileW
        self.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self.CreateFileW.restype = ctypes.c_void_p
        self.SetFileInformationByHandle = kernel.SetFileInformationByHandle
        self.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        self.SetFileInformationByHandle.restype = ctypes.c_int32
        self.CloseHandle = kernel.CloseHandle
        self.CloseHandle.argtypes = [ctypes.c_void_p]
        self.CloseHandle.restype = ctypes.c_int32
        self.last_error, self.error = last_error, error


def _load_api():
    return _WindowsAPI(ctypes.WinDLL('kernel32', use_last_error=True), ctypes.get_last_error, ctypes.WinError)


def _replace_windows(source, destination, *, api=None):
    source, destination = _absolute_file(source), _absolute_file(destination)
    parent = ntpath.dirname(source)
    if (ntpath.normcase(source) == ntpath.normcase(destination)
            or ntpath.normcase(parent) != ntpath.normcase(ntpath.dirname(destination))):
        raise ValueError('fixture replacement requires distinct files in the same parent')
    storage = _rename_buffer(destination)
    _ordinary(parent, directory=True)
    _ordinary(source)
    try:
        _ordinary(destination)
    except FileNotFoundError:
        pass
    if api is None:
        api = _load_api()
    handle = api.CreateFileW(source, 0x10000, 7, None, 3, 0x200000, None)
    if handle in (None, 0, -1, INVALID_HANDLE_VALUE):
        code = api.last_error()
        raise api.error(code)
    primary = None
    try:
        if not api.SetFileInformationByHandle(handle, 22, ctypes.byref(storage), ctypes.sizeof(storage)):
            code = api.last_error()
            raise api.error(code)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if not api.CloseHandle(handle):
                code = api.last_error()
                raise api.error(code)
        except BaseException as close_error:
            if primary is None:
                raise
            primary.close_error = close_error
            primary.add_note(f'CloseHandle also failed: {close_error}')


def replace(source, destination):
    if sys.platform == 'win32':
        _replace_windows(source, destination)
    else:
        os.replace(source, destination)
