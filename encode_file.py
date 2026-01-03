#!/usr/bin/env python3

import argparse, base64, getpass, glob, gzip, math, os, pathlib, PIL.ImageDraw, PIL.ImageOps, platform, qrcode, subprocess, sys, tempfile

ap = argparse.ArgumentParser(
        prog = 'encode_file',
        description = 'Encodes a file in two extremely redundant ways'
    )
ap.add_argument('filename',
    help = 'The file to encode')
ap.add_argument('name_of_file',
    nargs = '?',
    help = 'Optional name to use for the file instead of the file name')
ap.add_argument('--is-age-file',
    action = 'store_true',
    help = 'File name is an already encrypted AGE file')
args = ap.parse_args(sys.argv[1:])
if len(sys.argv) < 2:
    ap.print_help()
    sys.exit(0)
if args.name_of_file is None:
    args.name_of_file = args.filename
if not args.is_age_file:
    with open(args.filename, 'rb') as ih:
        filecontent = gzip.compress(ih.read())
    print(f"Filename compressed length {len(filecontent)} '{args.name_of_file}'")
    if len(filecontent) > 2048:
        print(f"FATAL: Only small files less than 2Kb can be encoded. This one is {len(filecontent)} bytes long.", file = sys.stderr)
        sys.exit(1)
    while True:
        password = getpass.getpass(
            prompt = 'Password (min 16 mixed letters, capitalisation, numbers and symbols): ')
        if len(password) < 16:
            print(f"That password is {len(password)} characters long! Enter it again!")
        else:
            break
    cpassword = gzip.compress(password.encode('utf-8'))
    password_entropy_estimate = (len(cpassword) - 20)
    print(f"That password of length {len(password)} is estimated to have an **upper bound** of {password_entropy_estimate * 8} bits of uniqueness.")
    if password_entropy_estimate < 20:
        print("    WARNING: You really should use a password with at least 160 bits of uniqueness!", file = sys.stderr)
    password_crack_time = pow(60, (password_entropy_estimate - 7)) / 10000000
    password_crack_time2 = pow(60, (password_entropy_estimate / 2 - 7)) / 10000000
    print(f"That password is estimated to take {password_crack_time} years to crack using 120 million top range 2023 GPUs. Be aware that future quantum computers may reduce that to {password_crack_time2} years.")
    if password_crack_time2 < 1:
        print("    WARNING: You really should use a password which would last a year being brute forced by a quantum computer!", file = sys.stderr)

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
elif platform.machine() == 'arm64' or platform.machine() == 'aarch64':
    prefix += 'arm64'
else:
    print(f"FATAL: Unknown machine {platform.machine()}", file = sys.stderr)
    sys.exit(1)
if args.is_age_file:
    outfile = args.name_of_file
    with open(outfile, 'rb') as ih:
        filecontent = base64.b64encode(ih.read())
    print(f"Encrypted file '{outfile}' is {len(filecontent)} bytes long.")
else:
    outfile = args.name_of_file + '.age'
    print("\nage will now ask you for the same password twice securely:")
    subprocess.run([f'{prefix}/age', '--encrypt', '--passphrase', '-o', outfile],
        input = filecontent, check = True)
    with open(outfile, 'rb') as ih:
        filecontent = base64.b64encode(ih.read())
    print(f"Encrypted file '{outfile}' is {len(filecontent)} bytes long.")

# Make the QR code
img = qrcode.make(filecontent,
    error_correction = qrcode.constants.ERROR_CORRECT_M)
img = PIL.ImageOps.expand(img.get_image(), border = (0, 50, 0, 0), fill = 'white')
PIL.ImageDraw.Draw(img).text((0,0), os.path.basename(args.name_of_file), font_size = 34)
outfileimg = outfile + '.png'
print(f"Encrypted file is saved as a printable QR code at '{outfileimg}'.")
img.save(outfileimg)

# Make the parity files with 64 times redundancy
for p in glob.glob(outfile + '*.par2'):
    os.remove(p)
subprocess.run([f'{prefix}/par2', 'create', '-r800', '-n8',
    outfile + '.par2', '--', outfile], check = True)

# Launch the decrypt script, and make sure what it outputs exactly
# matches what went in
print("\nDecode files script will once again ask you for the password securely:")
res = subprocess.run([os.getcwd() + '/decode_file.py', outfile],
    capture_output = True, check = True)
filecontent = res.stdout[res.stdout.find(b'---') + 4:]
with open(args.filename, 'rb') as ih:
    filecontent2 = ih.read()
    if filecontent != filecontent2:
        print(filecontent)
        print(filecontent2)
    assert filecontent == filecontent2
print("The decode files script output exactly matches the input file content!")

print("\nDecode QR code script will for a final time ask you for the password securely:")
res = subprocess.run([os.getcwd() + '/decode_file.py', '--qrcode-and-decrypt', outfile + '.png'],
    capture_output = True, check = True)
filecontent = res.stdout[res.stdout.find(b'---') + 4:]
with open(args.filename, 'rb') as ih:
    filecontent2 = ih.read()
    if filecontent != filecontent2:
        print(filecontent)
        print(filecontent2)
    assert filecontent == filecontent2
print("The decode QR code script output exactly matches the input file content!")
