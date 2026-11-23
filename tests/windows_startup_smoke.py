"""Explicit Windows bootstrap acceptance; isolated files, fresh venv, no AWS accounts.

Run with ``python tests/windows_startup_smoke.py``. This is separate from unit tests
because it deliberately installs runtime dependencies in a new environment.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def probe(source: Path, timeout: int = 360) -> dict:
    if os.name != 'nt':
        raise RuntimeError('This acceptance check requires Windows')
    base = Path(tempfile.mkdtemp(prefix='quickpool windows startup '))
    project = base / 'project with spaces'
    project.mkdir()
    # A real restart has an existing top-level data/ directory. It must not be
    # mistaken for another Python package during the editable installation.
    data = project / 'data'
    data.mkdir()
    (data / 'existing-state.txt').write_text('Existing runtime data must be preserved.')
    for name in ('pyproject.toml', 'README.md', 'LICENSE', 'start.ps1', 'start.cmd'):
        path = source / name
        if path.exists():
            shutil.copy2(path, project / name)
    shutil.copytree(source / 'quickpool', project / 'quickpool', ignore=shutil.ignore_patterns('__pycache__'))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('QUICKPOOL_')}
    env.update(QUICKPOOL_HOST='127.0.0.1', QUICKPOOL_PORT=str(port),
               QUICKPOOL_DATA_DIR=str(data), PYTHONUNBUFFERED='1',
               PYTHONDONTWRITEBYTECODE='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
    powershell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    direct = [powershell, '-NoProfile', '-ExecutionPolicy', 'Restricted', '-Command',
              "$ErrorActionPreference='Stop'; & '.\\start.ps1'"]
    denied = subprocess.run(direct, cwd=project, env=env, capture_output=True, timeout=20, check=False)
    report = {'project': str(project), 'fresh_venv': not (project / '.venv').exists(),
              'direct_command': direct, 'direct_exit_status': denied.returncode,
              'direct_stdout': denied.stdout.decode('utf-8', 'replace'),
              'direct_stderr': denied.stderr.decode('utf-8', 'replace'),
              'health_http': None, 'ready': False}
    command = [powershell, '-NoProfile', '-ExecutionPolicy', 'Restricted', '-Command',
               "$ErrorActionPreference='Stop'; & '.\\start.cmd'"]
    report['launcher_command'] = command
    assert denied.returncode != 0, 'The restricted-policy baseline unexpectedly ran'
    start = time.monotonic()
    stdout_path, stderr_path = base / 'startup.stdout', base / 'startup.stderr'
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        process = subprocess.Popen(command, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        try:
            while time.monotonic() - start < timeout:
                if process.poll() is not None:
                    break
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=1) as response:
                        body = json.load(response)
                        report.update(health_http=response.status, health=body, ready=body['status'] == 'ok')
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(.25)
            if report['ready']:
                admin = (data / 'admin.key').read_text().strip()
                api = (data / 'api.key').read_text().strip()
                assert admin and api and admin != api
                request = urllib.request.Request(f'http://127.0.0.1:{port}/api/overview',
                                                 headers={'Authorization': 'Bearer ' + admin})
                with urllib.request.urlopen(request, timeout=10) as response:
                    report['account_count'] = len(json.load(response)['accounts'])
                assert report['account_count'] == 0
                report['separate_management_and_api_keys'] = True
                assert (data / 'existing-state.txt').read_text() == 'Existing runtime data must be preserved.'
                report['existing_data_directory_preserved'] = True
        finally:
            report['launcher_exit_before_cleanup'] = process.poll()
            if process.poll() is None:
                cleanup = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                         capture_output=True, check=False)
                report['cleanup_exit_status'] = cleanup.returncode
            process.wait(timeout=30)
            report['launcher_exit_status'] = process.returncode
    report['elapsed_seconds'] = round(time.monotonic() - start, 2)
    report['stdout'] = stdout_path.read_bytes().decode('utf-8', 'replace')
    report['stderr'] = stderr_path.read_bytes().decode('utf-8', 'replace')
    report['evidence_directory'] = str(base)
    return report


if __name__ == '__main__':
    result = probe(Path(__file__).resolve().parents[1])
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    assert result['fresh_venv'] and result['ready'] and result['health_http'] == 200
