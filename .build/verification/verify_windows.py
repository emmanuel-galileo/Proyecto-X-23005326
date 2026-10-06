from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = Path(__file__).parent
INCLUDE = WORK / 'include'
GCC = r'C:\msys64\ucrt64\bin\gcc.exe'
ENV = dict(os.environ)
ENV['PATH'] = str(Path(GCC).parent) + os.pathsep + ENV['PATH']
ENV['TMP'] = ENV['TEMP'] = str(WORK)
FLAGS = ['-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', '-std=c99',
         '-D_POSIX_C_SOURCE=200809L', '-D_DEFAULT_SOURCE', '-I' + str(INCLUDE), '-I' + str(ROOT)]

def build(name, sources, extra=()):
    command = [GCC] + FLAGS + list(extra) + [str(ROOT / source) for source in sources]
    command += ['-o', str(WORK / (name + '.exe')), '-lws2_32', '-lwinpthread']
    result = subprocess.run(command, cwd=ROOT, env=ENV, text=True, capture_output=True)
    print(name + ' build:', result.returncode)
    if result.stderr: print(result.stderr)
    result.check_returncode()

def run(name, arguments=(), expected=0):
    command = [str(WORK / (name + '.exe'))] + list(arguments)
    result = subprocess.run(command, cwd=ROOT, env=ENV, text=True, capture_output=True, timeout=10)
    print(name, list(arguments), 'exit:', result.returncode, result.stdout.strip())
    if result.returncode != expected: print(result.stderr)
    assert result.returncode == expected

core = ['ip_header.c', 'udp_header.c', 'icmp_parser.c', 'checksum.c']
production = ['traceroute_main.c', 'traceroute_cli.c', 'traceroute_engine.c',
              'traceroute_output.c', 'dns_resolver.c', 'raw_socket.c'] + core
compat = ['.build/verification/windows_socket_compat.c']
forced = ['-include', str(INCLUDE / 'windows_socket_compat.h')]
build('test_core', ['tests/test_core.c', 'traceroute_cli.c'] + core)
build('test_engine', ['tests/test_engine.c', 'traceroute_engine.c', 'traceroute_output.c'] + core,
      ['-include', str(INCLUDE / 'test_clock.h')])
build('test_raw_socket', ['tests/test_raw_socket.c', 'raw_socket.c'] + compat, forced)
build('traceroute_windows_check', production + compat, forced)
run('test_core')
run('test_engine')
run('test_raw_socket')
run('traceroute_windows_check', ['--help'])
run('traceroute_windows_check', ['-q', '256', 'example.com'], 1)
run('traceroute_windows_check', ['-w', '0', 'example.com'], 1)
