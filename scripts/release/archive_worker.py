"""Dedicated archive parser entry point, independent of the caller's main."""
import json
from pathlib import Path
import sys

# Isolated Python omits the script directory; only this trusted directory is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from archives import Limits, _ERROR_LIMIT, _REQUEST_LIMIT, parse
from release_common import bounded_read, decode


def main():
    request, result = map(Path, sys.argv[1:])
    error = None
    try:
        values = decode(bounded_read(request, _REQUEST_LIMIT), 'archive worker request')
        if not isinstance(values, dict) or set(values) != {'path', 'kind', 'wanted',
                                                          'expected', 'limits'}:
            raise ValueError('invalid archive worker request')
        parse(Path(values['path']), values['kind'], values['wanted'], values['expected'],
              Limits(**values['limits']))
    except Exception as failure:
        error = str(failure).encode('utf-8', errors='replace')[:_ERROR_LIMIT].decode(
            'utf-8', errors='ignore')
    with result.open('xb') as stream:
        stream.write(json.dumps({'error': error}, ensure_ascii=False,
                                allow_nan=False).encode('utf-8'))


if __name__ == '__main__':
    main()
