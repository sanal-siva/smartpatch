"""Pinned SONiC source checkout. SBOMs are separate release artifacts."""
import re
import os
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from .process import run_bounded


RELEASE = re.compile(r'^sonic\.(?P<branch>[A-Za-z0-9_.-]+)\.(?P<build>[A-Za-z0-9_]+)-(?P<commit>[0-9a-fA-F]{7,64})$')


def parse_sonic_release(value):
    match = RELEASE.fullmatch(value)
    if not match:
        raise ValueError('expected sonic.<branch>.<build-id>-<commit-id>')
    return {'branch': match['branch'], 'build_id': match['build'], 'commit': match['commit'].lower()}


class GitHubSync:
    def __init__(self, repo_url='https://github.com/sonic-net/sonic-buildimage', local_path='/tmp/smart-patch-sources/sonic-buildimage'):
        parsed = urlparse(repo_url)
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError('repository must be an HTTPS URL without embedded credentials')
        self.repo_url, self.local_path, self.last_error, self.resolved_commit = repo_url, Path(local_path), None, None
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0',
                        GIT_ASKPASS='/bin/false', GIT_ALLOW_PROTOCOL='https', GIT_OPTIONAL_LOCKS='0')
        self.command = ['git', '-c', 'credential.helper=', '-c', 'http.extraHeader=',
                        '-c', 'http.followRedirects=false', '-c', 'http.sslVerify=true', '-c', 'core.hooksPath=/dev/null']

    def clone_repo(self, branch, commit):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,127}', branch or '') or '..' in branch:
            raise ValueError('invalid branch')
        if commit and not re.fullmatch(r'[0-9a-fA-F]{7,64}', commit):
            raise ValueError('commit must be a hexadecimal revision')
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            host = urlparse(self.repo_url)
            addresses = socket.getaddrinfo(host.hostname, host.port or 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
                raise ValueError('Source repository must resolve only to public addresses')
            if not self.local_path.exists():
                run_bounded([*self.command, 'clone', '--no-checkout', '--single-branch', '--branch', branch,
                             '--', self.repo_url, str(self.local_path)], timeout=600, max_bytes=4 * 1024 * 1024, env=self.env)
            else:
                actual = run_bounded([*self.command, '-C', str(self.local_path), 'remote', 'get-url', 'origin'], env=self.env).strip()
                if actual.rstrip('/') != self.repo_url.rstrip('/'):
                    raise ValueError('existing source checkout has a different origin')
                run_bounded([*self.command, '-C', str(self.local_path), 'fetch', '--no-tags', 'origin', branch], timeout=600, max_bytes=4 * 1024 * 1024, env=self.env)
            revision = commit or 'FETCH_HEAD'
            if not commit:
                revision = 'refs/remotes/origin/' + branch
            self.resolved_commit = run_bounded([*self.command, '-C', str(self.local_path), 'rev-parse', '--verify', revision + '^{commit}'], env=self.env).strip()
            # Read-only tools use git objects; no mutable checkout is needed.
            self.last_error = None
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def get_sbom_path(self):
        raise FileNotFoundError('SONiC SBOMs are release sidecar artifacts; configure an SBOM artifact URL/path, not the source repository root')
