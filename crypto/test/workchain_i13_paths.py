"""Allocate fresh evidence for explicitly registered private CTest drivers."""
from pathlib import Path
import tempfile


def resolve_ctest_paths(parser, args):
    if args.ctest_root is not None:
        if args.work is not None or args.output is not None:
            parser.error('--ctest-root cannot be combined with --work or --output')
        args.ctest_root.mkdir(parents=True, exist_ok=True)
        run = Path(tempfile.mkdtemp(prefix='run-', dir=args.ctest_root))
        args.work = run / 'work'
        args.output = run / 'evidence'
        print('Private measurement evidence: ' + str(args.output), flush=True)
    elif args.work is None or args.output is None:
        parser.error('--work and --output are required without --ctest-root')
