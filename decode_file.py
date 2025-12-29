#!/usr/bin/env python3

import argparse, base64, glob, os, PIL.Image, platform, qrcode, subprocess, sys, tempfile

import compression.gzip as gzip

ap = argparse.ArgumentParser(
        prog = 'decode_file',
        description = 'Decodes a file which was encoded in two extremely redundant ways'
    )
ap.add_argument('filename', help = 'The file to decode')
ap.add_argument('-o', '--output', help = 'File to write output into')
ap.add_argument('-q', '--qrcode', action = 'store_true', help = 'The input file is an image of a QR code (requires zbarimg installed), output its .age file.')
ap.add_argument('-qd', '--qrcode-and-decrypt', action = 'store_true', help = 'The input file is an image of a QR code (requires zbarimg installed), decrypt immediately.')
args = ap.parse_args(sys.argv[1:])
if len(sys.argv) < 2:
    ap.print_help()
    sys.exit(0)
parfiles = glob.glob(os.path.join(os.path.dirname(args.filename), '*.par2'))
if not parfiles:
    print(f"FATAL: No parity files found.", file = sys.stderr)
    sys.exit(1)
prefix = os.getcwd()
if platform.system() == 'Darwin':
    prefix += '/mac_'
elif platform.system() == 'Linux':
    prefix += '/linux_'
else:
    print(f"FATAL: Unknown platform {platform.system()}", file = sys.stderr)
    sys.exit(1)
if platform.machine() == 'AMD64':
    prefix += 'x64'
elif platform.machine() == 'arm64':
    prefix += 'arm64'
else:
    print(f"FATAL: Unknown machine {platform.machine()}", file = sys.stderr)
    sys.exit(1)
if args.qrcode or args.qrcode_and_decrypt:
    res = subprocess.run(['zbarimg', '--raw', args.filename], capture_output = True, check = True)
    filecontent = base64.b64decode(res.stdout)
else:
    subprocess.run([f'{prefix}/par2', 'repair', parfiles[0],
        '--', args.filename], check = True)
    with open(args.filename, 'rb') as ih:
        filecontent = ih.read()
if not args.qrcode or args.qrcode_and_decrypt:
    print("\nage will now ask you for the password securely:")
    sys.stdout.flush()
    res = subprocess.run([f'{prefix}/age', '--decrypt'],
        input = filecontent, capture_output = True, check = True)
    output = gzip.decompress(res.stdout)
else:
    output = filecontent
if args.output:
    with open(args.output, 'wb') as oh:
        oh.write(output)
else:
    sys.stdout.buffer.write(b'---\n')
    sys.stdout.buffer.write(output)
