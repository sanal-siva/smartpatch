"""Bounded CycloneDX/SPDX import with bundled offline standard schemas.

CycloneDX 1.4-1.6 and SPDX 2.3 receive full schema plus inventory checks.
The legacy SPDX 2.2 path validates the inventory import profile only.
"""
import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, parse_qs
from urllib.request import Request, urlopen
from .json_source import format_path, path_parts, locate


class SBOMValidationError(ValueError):
    def __init__(self, message, path='$', line=None, column=None):
        self.message=message
        self.path_parts=path_parts(path)
        if isinstance(path,(tuple,list)):path=format_path(path)
        self.path, self.line, self.column = path, line, column
        super().__init__(f'{path}: {message}' + (f' (line {line}, column {column})' if line else ''))


def stable_id(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _text(value, path, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise SBOMValidationError('expected a nonempty string, maximum 4096 characters', path)
    return value


def purl_fields(purl):
    if not purl or not isinstance(purl, str) or not purl.startswith('pkg:'):
        return {}
    parsed = urlparse(purl)
    kind, _, rest = parsed.path.partition('/')
    identity, sep, version = rest.rpartition('@')
    if not sep:
        identity = rest
    qualifiers = parse_qs(parsed.query)
    return {'ecosystem': kind, 'name': unquote(identity.rsplit('/', 1)[-1]),
            'version': unquote(version) if sep else '', 'arch': qualifiers.get('arch', [''])[0]}


class SBOMParser:
    def __init__(self, max_bytes=32 * 1024 * 1024, timeout=30):
        self.current_sbom = None
        self.source_sha256 = None
        self.max_bytes, self.timeout = max_bytes, timeout

    def load_sbom(self, source):
        self.source_sha256 = None
        self.current_sbom = None
        if isinstance(source, dict):
            if len(json.dumps(source).encode()) > self.max_bytes:
                raise SBOMValidationError('document exceeds size limit')
            document = copy.deepcopy(source)
        else:
            source = str(source)
            if source.startswith(('http://', 'https://')):
                parsed = urlparse(source)
                if parsed.username or parsed.password:
                    raise SBOMValidationError('credentials in source URLs are forbidden')
                with urlopen(Request(source, headers={'Accept': 'application/json'}), timeout=self.timeout) as response:
                    if parsed.scheme == 'https' and urlparse(response.url).scheme != 'https':
                        raise SBOMValidationError('HTTPS downgrade rejected')
                    raw = response.read(self.max_bytes + 1)
            else:
                with Path(source).open('rb') as stream:
                    raw = stream.read(self.max_bytes + 1)
            if len(raw) > self.max_bytes:
                raise SBOMValidationError('document exceeds size limit')
            return self.load_bytes(raw)
        self.validate(document)
        self.current_sbom = document
        return document

    def load_bytes(self, raw):
        self.source_sha256=None
        self.current_sbom=None
        if len(raw)>self.max_bytes:raise SBOMValidationError('document exceeds size limit')
        self.source_sha256=hashlib.sha256(raw).hexdigest()
        try:
            source=raw.decode('utf-8-sig')
            document=json.loads(source)
        except json.JSONDecodeError as exc:
            raise SBOMValidationError(exc.msg,line=exc.lineno,column=exc.colno) from exc
        except UnicodeDecodeError as exc:
            raise SBOMValidationError('document is not UTF-8 JSON') from exc
        except RecursionError as exc:
            raise SBOMValidationError('JSON nesting exceeds the parser limit',line=1,column=1) from exc
        try:self.validate(document)
        except SBOMValidationError as exc:
            line,column=locate(source,exc.path_parts)
            raise SBOMValidationError(exc.message,exc.path_parts,line,column) from exc
        self.current_sbom=document
        return document

    def _flatten_paths(self, components, depth=0, path=('components',)):
        if depth > 32:
            raise SBOMValidationError('nesting exceeds 32 levels',path)
        if not isinstance(components, list):
            raise SBOMValidationError('components must be an array',path)
        for index,component in enumerate(components):
            child=(*path,index)
            if not isinstance(component, dict):
                raise SBOMValidationError('component must be an object',child)
            yield component,child
            yield from self._flatten_paths(component.get('components', []), depth + 1,(*child,'components'))

    def _flatten(self, components, depth=0):
        for component,_ in self._flatten_paths(components,depth):yield component

    def validate(self, document):
        if not isinstance(document, dict):
            raise SBOMValidationError('document must be an object')
        if document.get('bomFormat') == 'CycloneDX':
            if document.get('specVersion') not in {'1.4', '1.5', '1.6'}:
                raise SBOMValidationError('supported versions: 1.4, 1.5, 1.6', '$.specVersion')
            refs = set()
            metadata = document.get('metadata', {})
            if not isinstance(metadata, dict) or not isinstance(metadata.get('component', {}), dict):
                raise SBOMValidationError('metadata and metadata.component must be objects', '$.metadata')
            root = metadata.get('component', {})
            if root.get('bom-ref'):
                refs.add(root['bom-ref'])
            for component,parts in self._flatten_paths(document.get('components')):
                path = format_path(parts)
                _text(component.get('name'), path + '.name')
                _text(component.get('type'), path + '.type')
                if component['type'] not in {'application', 'framework', 'library', 'container', 'platform', 'operating-system',
                                              'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset'}:
                    raise SBOMValidationError('unsupported component type', path + '.type')
                _text(component.get('version'), path + '.version', False)
                ref = component.get('bom-ref')
                if ref is not None:
                    _text(ref, path + '.bom-ref')
                    if ref in refs:
                        raise SBOMValidationError('duplicate component reference', path + '.bom-ref')
                    refs.add(ref)
                purl = component.get('purl')
                if purl is not None and (not isinstance(purl, str) or not purl.startswith('pkg:')):
                    raise SBOMValidationError('invalid package URL', path + '.purl')
                properties = component.get('properties', [])
                if not isinstance(properties, list) or any(not isinstance(p, dict) or not isinstance(p.get('name'), str)
                    or not isinstance(p.get('value'), str) for p in properties):
                    raise SBOMValidationError('properties must contain string name/value objects', path + '.properties')
                if not isinstance(component.get('pedigree', {}), dict):
                    raise SBOMValidationError('pedigree must be an object', path + '.pedigree')
            if not isinstance(document.get('dependencies', []), list):
                raise SBOMValidationError('dependencies must be an array', '$.dependencies')
            for index, dep in enumerate(document.get('dependencies', [])):
                if not isinstance(dep, dict) or dep.get('ref') not in refs:
                    raise SBOMValidationError('unresolved dependency reference', f'$.dependencies[{index}]')
                if not isinstance(dep.get('dependsOn', []), list) or any(ref not in refs for ref in dep.get('dependsOn', [])):
                    raise SBOMValidationError('unresolved dependsOn reference', f'$.dependencies[{index}]')
        elif document.get('spdxVersion') in {'SPDX-2.2', 'SPDX-2.3'}:
            _text(document.get('SPDXID'), '$.SPDXID')
            _text(document.get('documentNamespace'), '$.documentNamespace')
            if not isinstance(document.get('packages'), list):
                raise SBOMValidationError('packages must be an array', '$.packages')
            refs = {document['SPDXID']}
            for index, package in enumerate(document['packages']):
                if not isinstance(package, dict):
                    raise SBOMValidationError('package must be an object', f'$.packages[{index}]')
                _text(package.get('name'), f'$.packages[{index}].name')
                ref = _text(package.get('SPDXID'), f'$.packages[{index}].SPDXID')
                if ref in refs:
                    raise SBOMValidationError('duplicate SPDXID', f'$.packages[{index}].SPDXID')
                refs.add(ref)
                _text(package.get('versionInfo'), f'$.packages[{index}].versionInfo', False)
                external = package.get('externalRefs', [])
                if not isinstance(external, list) or any(not isinstance(ref, dict) or not isinstance(ref.get('referenceType'), str)
                    or not isinstance(ref.get('referenceLocator'), str) for ref in external):
                    raise SBOMValidationError('externalRefs must contain referenceType/referenceLocator objects', f'$.packages[{index}].externalRefs')
        else:
            raise SBOMValidationError('expected CycloneDX 1.4-1.6 or SPDX 2.2-2.3 JSON')
        schema_name = ('bom-' + document['specVersion'] + '.schema.json') if document.get('bomFormat') == 'CycloneDX' else ('spdx-2.3.schema.json' if document.get('spdxVersion') == 'SPDX-2.3' else None)
        if schema_name:
            self._validate_offline_schema(document, schema_name)
        return {'valid': True, 'validation_profile': 'smart-patch-inventory-v1', 'schema_validated': bool(schema_name), 'schema': schema_name}

    @staticmethod
    def _validate_offline_schema(document, schema_name):
        import jsonschema
        folder = Path(__file__).with_name('schemas')
        schemas = {path.name: json.loads(path.read_text()) for path in folder.glob('*.schema.json')}
        schema = schemas[schema_name]
        store = {value.get('$id', value.get('id')): value for value in schemas.values()}
        store.update(schemas)
        def deny_external(uri):
            raise SBOMValidationError('schema reference is not bundled: ' + uri)
        # All references belong to bundled schemas; resolving a URL must never fetch a network resource.
        resolver = jsonschema.RefResolver.from_schema(schema, store=store,
                   handlers={'http': deny_external, 'https': deny_external, 'file': deny_external})
        validator = jsonschema.validators.validator_for(schema)(schema, resolver=resolver,
                    format_checker=jsonschema.FormatChecker())
        error = next(validator.iter_errors(document), None)
        if error is not None:
            raise SBOMValidationError(error.message[:1000], tuple(error.absolute_path))

    def parse_packages(self, sbom):
        self.validate(sbom)
        packages = []
        if sbom.get('bomFormat') == 'CycloneDX':
            for component in self._flatten(sbom['components']):
                props = {p.get('name'): p.get('value') for p in component.get('properties', []) if isinstance(p, dict)}
                packages.append({**purl_fields(component.get('purl')), 'id': component.get('bom-ref') or stable_id(component),
                                 'bom_ref': component.get('bom-ref'), 'name': component['name'],
                                 'version': component.get('version'), 'type': component['type'],
                                 'metadata_type_source': 'cyclonedx.type',
                                 'purl': component.get('purl', ''), 'properties': props,
                                 'hashes': copy.deepcopy(component.get('hashes', [])),
                                 'external_references': copy.deepcopy(component.get('externalReferences', [])),
                                 'patches': copy.deepcopy(component.get('pedigree', {}).get('patches', []))})
        else:
            for package in sbom['packages']:
                purl = next((ref.get('referenceLocator', '') for ref in package.get('externalRefs', []) if ref.get('referenceType') == 'purl'), '')
                packages.append({**purl_fields(purl), 'id': package['SPDXID'], 'bom_ref': package['SPDXID'],
                                 'name': package['name'], 'version': package.get('versionInfo'),
                                 'type': 'library', 'purl': purl, 'properties': {}, 'patches': []})
        return packages

    def to_inventory(self, sbom, build_id=None):
        packages = self.parse_packages(sbom)
        containers = {p['id']: p for p in packages if p['type'] == 'container'}
        graph = {d['ref']: d.get('dependsOn', []) for d in sbom.get('dependencies', [])}
        root = sbom.get('metadata', {}).get('component', {})
        root_ref = root.get('bom-ref')
        scopes, assigned, warnings = [], set(), []
        def reachable(start):
            seen, pending = set(), list(graph.get(start, []))
            while pending:
                child = pending.pop()
                if child in seen or child in containers:
                    continue
                seen.add(child)
                pending.extend(graph.get(child, []))
            return seen
        def separate(items):
            structural = [p for p in items if not p.get('purl') and p.get('type') in {'operating-system', 'platform', 'container'}]
            structural_ids = {p['id'] for p in structural}
            return [p for p in items if p['id'] not in structural_ids], structural
        for ref, container in containers.items():
            seen = reachable(ref)
            scoped = [copy.deepcopy(p) for p in packages if p['id'] in seen]
            components, metadata = separate(scoped)
            assigned.update(seen)
            props = container.get('properties', {})
            explicit_image = next((props[key] for key in ('smart-patch:image_digest', 'sonic:image_digest', 'sonic:image-digest') if props.get(key)), None)
            scopes.append({'id': ref, 'kind': 'container', 'name': container['name'], 'container_ref': ref,
                           'components': components, 'metadata_components': metadata, 'distro': self._infer_distro(scoped),
                           'properties': props, 'purl': container.get('purl'), 'hashes': container.get('hashes', []),
                           'external_references': container.get('external_references', []), 'image_digest': explicit_image,
                           'image_digest_kind': 'explicit_property' if explicit_image else 'not_asserted',
                           'identity_note': 'Component hashes may identify an archive; they are not assumed to be runtime OCI image digests'})
        if root_ref and root_ref in graph:
            host_ids = reachable(root_ref)
            host_all = [p for p in packages if p['id'] in host_ids]
            assigned.update(host_ids)
            host_basis = 'explicit_root_containment'
            unattributed = [p for p in packages if p['id'] not in assigned and p['id'] not in containers]
            if unattributed:
                components, metadata = separate(unattributed)
                if components:
                    scopes.append({'id': 'unattributed', 'kind': 'unknown', 'components': components,
                                   'metadata_components': metadata, 'distro': self._infer_distro(unattributed)})
                    warnings.append('Some components are not reachable from the declared root; their deployment scope is unknown')
        else:
            host_all = [p for p in packages if p['id'] not in assigned and p['id'] not in containers]
            host_basis = 'legacy_unrooted_fallback'
            warnings.append('SBOM has no rooted containment graph; the fallback host scope does not prove component presence or absence')
        host, metadata = separate(host_all)
        scopes.insert(0, {'id': 'host', 'kind': 'host', 'components': host, 'metadata_components': metadata,
                          'distro': self._infer_distro(host_all), 'scope_assignment': host_basis,
                          'properties': {p['id']: p.get('properties', {}) for p in metadata}})
        return {'build_id': build_id or sbom.get('serialNumber') or sbom.get('documentNamespace'),
                'scopes': scopes, 'coverage_warnings': warnings}

    @staticmethod
    def _infer_distro(components):
        explicit = set()
        for component in components:
            props = component.get('properties', {})
            name = props.get('syft:distro:id') or props.get('smart-patch:distro:name')
            version = props.get('syft:distro:versionID') or props.get('smart-patch:distro:version')
            if name and version:
                explicit.add((name, version))
        if len(explicit) == 1:
            name, version = next(iter(explicit))
            return {'name': name, 'version': version}
        if explicit:
            return {}  # conflicting OS metadata cannot establish a distro scope
        inferred = set()
        for component in components:
            qualifier = parse_qs(urlparse(component.get('purl') or '').query).get('distro', [''])[0]
            if qualifier:
                name, separator, version = qualifier.rpartition('-')
                if separator and name and version:
                    inferred.add((name, version))
        if len(inferred) == 1:
            name, version = next(iter(inferred))
            return {'name': name, 'version': version}
        return {}


def normalize_inventory(inventory):
    if not isinstance(inventory, dict):
        raise SBOMValidationError('inventory must be an object')
    if inventory.get('bomFormat') or inventory.get('spdxVersion'):
        inventory = SBOMParser().to_inventory(inventory)
    elif inventory.get('sbom') and not inventory.get('scopes'):
        inventory = {**inventory, **SBOMParser().to_inventory(inventory['sbom'], inventory.get('build_id'))}
    result = copy.deepcopy(inventory)
    if not isinstance(result.get('scopes'), list) or not result['scopes']:
        raise SBOMValidationError('at least one scope is required', '$.scopes')
    seen = set()
    for index, scope in enumerate(result['scopes']):
        if not isinstance(scope, dict):
            raise SBOMValidationError('scope must be an object', f'$.scopes[{index}]')
        scope_id = _text(scope.get('id') or scope.get('scope_id'), f'$.scopes[{index}].id')
        if scope_id in seen:
            raise SBOMValidationError('duplicate scope id', f'$.scopes[{index}].id')
        seen.add(scope_id)
        scope['id'] = scope_id
        if not isinstance(scope.get('components'), list):
            raise SBOMValidationError('components must be an array', f'$.scopes[{index}].components')
        component_ids = set()
        for cindex, component in enumerate(scope['components']):
            path = f'$.scopes[{index}].components[{cindex}]'
            if not isinstance(component, dict):
                raise SBOMValidationError('component must be an object', path)
            component['name'] = _text(component.get('name') or component.get('package_name'), path + '.name')
            component['version'] = _text(component.get('version') or component.get('installed_version'), path + '.version', False)
            for key, value in purl_fields(component.get('purl')).items():
                if value and not component.get(key):
                    component[key] = value
            component['id'] = str(component.get('id') or component.get('component_id') or component.get('bom_ref') or stable_id([scope_id, component.get('purl'), component['name'], component['version'], component.get('arch')]))
            if component['id'] in component_ids:
                raise SBOMValidationError('duplicate component id in scope', path + '.id')
            component_ids.add(component['id'])
    return result


def scope_to_sbom(scope):
    components = []
    for package in scope['components']:
        if not package.get('version'):
            continue
        kind = package.get('ecosystem') or package.get('type', 'deb')
        kind = {'dpkg': 'deb', 'python': 'pypi', 'library': 'generic', 'application': 'generic'}.get(kind, kind)
        purl = package.get('purl')
        if not purl:
            namespace = 'debian/' if kind == 'deb' else ''
            purl = f"pkg:{kind}/{namespace}{quote(package['name'], safe='')}@{quote(package['version'], safe='')}"
            if package.get('arch'):
                purl += '?arch=' + quote(package['arch'], safe='')
        props = package.get('properties', {})
        if isinstance(props, list):
            props = {p['name']: p['value'] for p in props if 'name' in p and 'value' in p}
        props = dict(props)
        if package.get('source_name'):
            props['syft:metadata:source'] = package['source_name']
        if package.get('source_version'):
            props['syft:metadata:sourceVersion'] = package['source_version']
        components.append({'type': 'library', 'bom-ref': package['id'], 'name': package['name'],
                           'version': package['version'], 'purl': purl,
                           'properties': [{'name': str(k), 'value': str(v)} for k, v in props.items() if v is not None]})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': components}
