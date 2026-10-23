#!/usr/bin/env python3
"""Check the review baseline for APK/OS wire compatibility, without an emulator.

This is not release qualification. Updating the baseline requires an API review;
it must never be regenerated implicitly by a build or packaging command.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import zipfile

ANDROID = Path(__file__).resolve().parents[1]
BASELINE = ANDROID / 'tests/fixtures/desktop-sdk-contract-v3.1.json'
IDENTIFIER = r'[A-Za-z_][A-Za-z0-9_]*'
QUALIFIED = IDENTIFIER + r'(?:\.' + IDENTIFIER + r')*'

# JVM access bits which affect whether an SDK type/member is linkable or how it
# is presented to Java/Kotlin callers.  The ledger records the numeric mask as
# emitted rather than relying on a tool-specific textual rendering.
PUBLIC_OR_PROTECTED = 0x0001 | 0x0004


class ClassFormatError(ValueError):
    """A malformed or unsupported class file cannot be an API baseline."""


class ClassReader:
    def __init__(self, payload, label):
        self.payload = payload
        self.label = label
        self.position = 0

    def take(self, size):
        end = self.position + size
        if size < 0 or end > len(self.payload):
            raise ClassFormatError('Truncated class file: ' + self.label)
        value = self.payload[self.position:end]
        self.position = end
        return value

    def u1(self):
        return self.take(1)[0]

    def u2(self):
        return int.from_bytes(self.take(2), 'big')

    def u4(self):
        return int.from_bytes(self.take(4), 'big')


def _modified_utf8(payload, label):
    """Decode the JVM's NUL/surrogate-capable modified UTF-8 exactly."""
    units = []
    position = 0
    while position < len(payload):
        first = payload[position]
        position += 1
        if 0 < first < 0x80:
            units.append(first)
        elif first & 0xe0 == 0xc0:
            if position >= len(payload) or payload[position] & 0xc0 != 0x80:
                raise ClassFormatError('Invalid modified UTF-8: ' + label)
            value = ((first & 0x1f) << 6) | (payload[position] & 0x3f)
            position += 1
            if value != 0 and value < 0x80:
                raise ClassFormatError('Overlong modified UTF-8: ' + label)
            units.append(value)
        elif first & 0xf0 == 0xe0:
            if (position + 1 >= len(payload) or payload[position] & 0xc0 != 0x80 or
                    payload[position + 1] & 0xc0 != 0x80):
                raise ClassFormatError('Invalid modified UTF-8: ' + label)
            value = ((first & 0x0f) << 12) | ((payload[position] & 0x3f) << 6) | \
                    (payload[position + 1] & 0x3f)
            position += 2
            if value < 0x800:
                raise ClassFormatError('Overlong modified UTF-8: ' + label)
            units.append(value)
        else:
            raise ClassFormatError('Invalid modified UTF-8 lead byte: ' + label)
    result = []
    position = 0
    while position < len(units):
        value = units[position]
        if 0xd800 <= value <= 0xdbff and position + 1 < len(units) and 0xdc00 <= units[position + 1] <= 0xdfff:
            result.append(chr(0x10000 + ((value - 0xd800) << 10) + units[position + 1] - 0xdc00))
            position += 2
        else:
            result.append(chr(value))
            position += 1
    return ''.join(result)


def _constant_pool(reader):
    count = reader.u2()
    if count < 1:
        raise ClassFormatError('Empty class constant pool: ' + reader.label)
    pool = [None] * count
    index = 1
    while index < count:
        tag = reader.u1()
        if tag == 1:
            length = reader.u2()
            value = _modified_utf8(reader.take(length), reader.label)
            pool[index] = ('Utf8', value)
        elif tag == 3:
            pool[index] = ('Integer', int.from_bytes(reader.take(4), 'big', signed=True))
        elif tag == 4:
            pool[index] = ('Float', reader.take(4).hex())
        elif tag == 5:
            pool[index] = ('Long', int.from_bytes(reader.take(8), 'big', signed=True))
            index += 1
            if index >= count:
                raise ClassFormatError('Invalid wide constant: ' + reader.label)
        elif tag == 6:
            pool[index] = ('Double', reader.take(8).hex())
            index += 1
            if index >= count:
                raise ClassFormatError('Invalid wide constant: ' + reader.label)
        elif tag in (7, 8, 16, 19, 20):
            names = {7: 'Class', 8: 'String', 16: 'MethodType',
                     19: 'Module', 20: 'Package'}
            pool[index] = (names[tag], reader.u2())
        elif tag in (9, 10, 11, 12, 17, 18):
            names = {9: 'Fieldref', 10: 'Methodref', 11: 'InterfaceMethodref',
                     12: 'NameAndType', 17: 'Dynamic', 18: 'InvokeDynamic'}
            pool[index] = (names[tag], reader.u2(), reader.u2())
        elif tag == 15:
            pool[index] = ('MethodHandle', reader.u1(), reader.u2())
        else:
            raise ClassFormatError('Unsupported constant-pool tag ' + str(tag) + ': ' + reader.label)
        index += 1
    return pool


def _pool_entry(pool, index, kind, label):
    if not 0 < index < len(pool) or pool[index] is None or pool[index][0] != kind:
        raise ClassFormatError('Invalid ' + kind + ' reference in ' + label)
    return pool[index]


def _utf8(pool, index, label):
    return _pool_entry(pool, index, 'Utf8', label)[1]


def _class_name(pool, index, label):
    return _utf8(pool, _pool_entry(pool, index, 'Class', label)[1], label)


def _attributes(reader, pool):
    result = []
    for _ in range(reader.u2()):
        name = _utf8(pool, reader.u2(), reader.label)
        result.append((name, reader.take(reader.u4())))
    return result


def _one_attribute(attributes, name, label):
    matches = [payload for candidate, payload in attributes if candidate == name]
    if len(matches) > 1:
        raise ClassFormatError('Duplicate ' + name + ' attribute: ' + label)
    return matches[0] if matches else None


def _signature(attributes, pool, label):
    payload = _one_attribute(attributes, 'Signature', label)
    if payload is None:
        return None
    if len(payload) != 2:
        raise ClassFormatError('Invalid Signature attribute: ' + label)
    return _utf8(pool, int.from_bytes(payload, 'big'), label)


def _constant_value(attributes, pool, label):
    payload = _one_attribute(attributes, 'ConstantValue', label)
    if payload is None:
        return None
    if len(payload) != 2:
        raise ClassFormatError('Invalid ConstantValue attribute: ' + label)
    index = int.from_bytes(payload, 'big')
    if not 0 < index < len(pool) or pool[index] is None:
        raise ClassFormatError('Invalid ConstantValue reference: ' + label)
    entry = pool[index]
    if entry[0] == 'String':
        return {'kind': 'String', 'value': _utf8(pool, entry[1], label)}
    if entry[0] not in {'Integer', 'Float', 'Long', 'Double'}:
        raise ClassFormatError('Unsupported ConstantValue kind: ' + label)
    return {'kind': entry[0], 'value': entry[1]}


def _exceptions(attributes, pool, label):
    payload = _one_attribute(attributes, 'Exceptions', label)
    if payload is None:
        return []
    nested = ClassReader(payload, label + ' Exceptions')
    result = [_class_name(pool, nested.u2(), label) for _ in range(nested.u2())]
    if nested.position != len(payload):
        raise ClassFormatError('Trailing Exceptions data: ' + label)
    return result


def _member(reader, pool, kind):
    access = reader.u2()
    name = _utf8(pool, reader.u2(), reader.label)
    descriptor = _utf8(pool, reader.u2(), reader.label)
    attributes = _attributes(reader, pool)
    if not access & PUBLIC_OR_PROTECTED:
        return None
    result = {'access': access, 'name': name, 'descriptor': descriptor}
    signature = _signature(attributes, pool, reader.label + ' ' + name)
    if signature is not None:
        result['signature'] = signature
    if kind == 'field':
        constant = _constant_value(attributes, pool, reader.label + ' ' + name)
        if constant is not None:
            result['constant'] = constant
    else:
        exceptions = _exceptions(attributes, pool, reader.label + ' ' + name)
        if exceptions:
            result['exceptions'] = exceptions
    return result


def _inner_access(attributes, pool, this_name, label):
    payload = _one_attribute(attributes, 'InnerClasses', label)
    if payload is None:
        return None
    nested = ClassReader(payload, label + ' InnerClasses')
    found = []
    for _ in range(nested.u2()):
        inner = nested.u2()
        nested.u2()  # outer_class_info_index, not part of the class descriptor
        nested.u2()  # inner_name_index, already represented by this_name
        access = nested.u2()
        if inner != 0 and _class_name(pool, inner, label) == this_name:
            found.append(access)
    if nested.position != len(payload) or len(found) > 1:
        raise ClassFormatError('Invalid self InnerClasses entry: ' + label)
    return found[0] if found else None


def class_abi(payload, expected_name):
    """Return one exported class's deterministic link-time JVM ABI.

    Method bodies, private implementation, debug tables and compiler metadata
    are deliberately excluded.  Public/protected descriptors, generic
    signatures, checked exceptions, field constants and type relationships are
    included.  A non-exported generated helper returns ``None``.
    """
    reader = ClassReader(payload, expected_name)
    if reader.u4() != 0xCAFEBABE:
        raise ClassFormatError('Invalid class magic: ' + expected_name)
    reader.u2()  # minor
    reader.u2()  # major: the release toolchain is pinned elsewhere
    pool = _constant_pool(reader)
    access = reader.u2()
    this_name = _class_name(pool, reader.u2(), expected_name)
    super_index = reader.u2()
    super_name = _class_name(pool, super_index, expected_name) if super_index else None
    interfaces = [_class_name(pool, reader.u2(), expected_name) for _ in range(reader.u2())]
    fields = []
    for _ in range(reader.u2()):
        member = _member(reader, pool, 'field')
        if member is not None:
            fields.append(member)
    methods = []
    for _ in range(reader.u2()):
        member = _member(reader, pool, 'method')
        if member is not None:
            methods.append(member)
    attributes = _attributes(reader, pool)
    if reader.position != len(payload):
        raise ClassFormatError('Trailing class data: ' + expected_name)
    if this_name + '.class' != expected_name:
        raise ClassFormatError('Class path/name mismatch: ' + expected_name)
    inner_access = _inner_access(attributes, pool, this_name, expected_name)
    exported = bool(access & 0x0001) or bool((inner_access or 0) & PUBLIC_OR_PROTECTED)
    if not exported:
        return None
    result = {
        'access': access,
        'super': super_name,
        'interfaces': interfaces,
        'fields': sorted(fields, key=lambda row: (row['name'], row['descriptor'])),
        'methods': sorted(methods, key=lambda row: (row['name'], row['descriptor'])),
    }
    if inner_access is not None:
        # Nested visibility lives in InnerClasses rather than access_flags.
        # Public -> protected is still a compatibility change and must not
        # collapse to the same ledger row.
        result['inner_access'] = inner_access
    signature = _signature(attributes, pool, expected_name)
    if signature is not None:
        result['signature'] = signature
    return result


def jvm_abi_from_entries(entries):
    class_files = sorted(name for name in entries if name.endswith('.class'))
    if not class_files:
        raise ClassFormatError('SDK contains no JVM class files')
    classes = {}
    for name in class_files:
        value = class_abi(entries[name], name)
        if value is not None:
            classes[name[:-6]] = value
    if not classes:
        raise ClassFormatError('SDK contains no exported JVM classes')
    return {'schema': 1, 'class_files': class_files, 'classes': classes}


def jvm_abi_from_jar(source):
    """Read a bounded, duplicate-free classes.jar without extracting it."""
    stream = io.BytesIO(source) if isinstance(source, bytes) else source
    try:
        archive = zipfile.ZipFile(stream)
    except (OSError, zipfile.BadZipFile) as error:
        raise ClassFormatError('Invalid SDK classes.jar') from error
    with archive:
        if archive.comment:
            raise ClassFormatError('SDK classes.jar has a ZIP comment')
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(infos) > 256 or len(names) != len(set(names)):
            raise ClassFormatError('Invalid SDK classes.jar entry set')
        entries = {}
        total = 0
        for info in infos:
            if info.is_dir() or not info.filename.endswith('.class'):
                continue
            if (not info.filename or info.filename.startswith('/') or '\\' in info.filename or
                    any(part in ('', '.', '..') for part in info.filename.split('/'))):
                raise ClassFormatError('Unsafe SDK class path: ' + info.filename)
            if info.file_size > 4 * 1024 * 1024:
                raise ClassFormatError('Oversized SDK class: ' + info.filename)
            total += info.file_size
            if total > 32 * 1024 * 1024:
                raise ClassFormatError('Oversized SDK classes.jar')
            try:
                entries[info.filename] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise ClassFormatError('Unreadable SDK class: ' + info.filename) from error
        return jvm_abi_from_entries(entries)


def quoted_end(value, start):
    quote = value[start]
    index = start + 1
    while index < len(value):
        if value[index] == '\\':
            index += 2
        elif value[index] == quote:
            return index + 1
        else:
            index += 1
    raise ValueError('Unterminated source string')


def without_comments(value):
    # A URL/comment marker inside a quoted annotation or constant is data.
    # Replace comments with whitespace, rather than concatenating type tokens.
    parts = []
    index = 0
    while index < len(value):
        if value[index] in ('"', "'"):
            end = quoted_end(value, index)
            parts.append(value[index:end])
            index = end
        elif value.startswith('//', index):
            end = value.find('\n', index + 2)
            end = len(value) if end < 0 else end
            parts.append(' ')
            index = end
        elif value.startswith('/*', index):
            end = value.find('*/', index + 2)
            if end < 0:
                raise ValueError('Unterminated source comment')
            comment = value[index:end + 2]
            parts.append(' ' + '\n' * comment.count('\n'))
            index = end + 2
        else:
            parts.append(value[index])
            index += 1
    return ''.join(parts)


def normalize(value):
    # Changing whitespace inside a Descriptor/string constant changes its value.
    return re.sub(r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|\s+',
                  lambda match: match[1] if match[1] is not None else ' ', value).strip()


def skip_space(source, position):
    while position < len(source) and source[position].isspace():
        position += 1
    return position


def balanced_end(source, position):
    """Consume annotation arguments; quoted punctuation never closes a group."""
    stack = []
    while position < len(source):
        char = source[position]
        if char in ('"', "'"):
            position = quoted_end(source, position)
            continue
        if char in '([':
            stack.append(char)
        elif char in ')]':
            if not stack or stack.pop() != {')': '(', ']': '['}[char]:
                raise ValueError('Unbalanced SDK annotation')
            if not stack:
                return position + 1
        elif char in '{};':
            raise ValueError('Unmodeled SDK annotation syntax')
        position += 1
    raise ValueError('Unterminated SDK annotation')


def aidl_contract(source, stem):
    """Consume exactly the structured AIDL subset supported by this SDK.

    Not an AIDL compiler: unsupported syntax fails closed and requires review,
    instead of being silently omitted from the compatibility snapshot.
    """
    package = re.match(r'\s*package\s+(' + QUALIFIED + r')\s*;', source)
    if package is None:
        raise ValueError('Unrecognized SDK package: ' + stem)
    position = skip_space(source, package.end())
    imports = []
    while True:
        item = re.match(r'import\s+(' + QUALIFIED + r')\s*;', source[position:])
        if item is None:
            break
        imports.append(item[1])
        position = skip_space(source, position + item.end())
    annotations = []
    while position < len(source) and source[position] == '@':
        start = position
        item = re.match(r'@' + IDENTIFIER + r'\b', source[position:])
        if item is None:
            raise ValueError('Unrecognized SDK type annotation: ' + stem)
        position = skip_space(source, position + item.end())
        if position < len(source) and source[position] == '(':
            position = balanced_end(source, position)
        annotations.append(normalize(source[start:position]))
        position = skip_space(source, position)
    declaration = re.match(r'((?:oneway\s+)?interface|parcelable)\s+(' +
                           IDENTIFIER + r')\s*\{', source[position:])
    if declaration is None or declaration[2] != stem:
        raise ValueError('Unrecognized SDK declaration: ' + stem)
    position += declaration.end()
    start = position
    rows = []
    stack = []
    while position < len(source):
        char = source[position]
        if char in ('"', "'"):
            position = quoted_end(source, position)
            continue
        if char in '([':
            stack.append(char)
        elif char in ')]':
            if not stack or stack.pop() != {')': '(', ']': '['}[char]:
                raise ValueError('Unbalanced SDK declaration: ' + stem)
        elif char == '{':
            raise ValueError('Unmodeled nested SDK declaration: ' + stem)
        elif char == ';':
            if stack:
                raise ValueError('Unmodeled SDK statement: ' + stem)
            row = normalize(source[start:position])
            if not row:
                raise ValueError('Empty SDK statement: ' + stem)
            rows.append(row)
            start = position + 1
        elif char == '}':
            if stack or source[start:position].strip():
                raise ValueError('Unterminated SDK declaration: ' + stem)
            if source[position + 1:].strip():
                raise ValueError('Unexpected trailing SDK syntax: ' + stem)
            result = {'package': package[1], 'kind': normalize(declaration[1]),
                      'imports': sorted(imports), 'declarations': rows}
            # The reviewed unannotated API3 baseline remains unchanged. Any
            # leading annotation, including Descriptor, now requires review.
            if annotations:
                result['annotations'] = annotations
            return result
        position += 1
    raise ValueError('Unterminated SDK declaration: ' + stem)


def protocol_constants(source):
    # DesktopProtocol intentionally has only single-line literal/shift constants.
    # Reject multiline expressions/properties rather than ignoring extra Kotlin.
    header = re.match(r'\s*package\s+' + QUALIFIED +
                      r'\s+object\s+DesktopProtocol\s*\{', source)
    if header is None or not source.rstrip().endswith('}'):
        raise ValueError('Unrecognized SDK protocol object')
    body = source[header.end():source.rfind('}')]
    constants = {}
    for row in body.splitlines():
        if not row.strip():
            continue
        item = re.fullmatch(r'\s*const\s+val\s+(' + IDENTIFIER + r')\s*=\s*(.*?)\s*', row)
        if item is None:
            raise ValueError('Unmodeled SDK protocol syntax')
        name, value = item.groups()
        if name in constants:
            raise ValueError('Duplicate SDK constant: ' + name)
        if not re.fullmatch(r'(?:\d+[Ll]?(?:\s+shl\s+\d+)?|"(?:\\.|[^"\\])*")', value):
            raise ValueError('Unmodeled SDK constant expression: ' + name)
        constants[name] = normalize(value)
    return constants


def binder_transactions(files):
    """Return the generated Binder method order for every public interface.

    AIDL assigns methods consecutively from FIRST_CALL_TRANSACTION in source
    order. Keeping the offset as well as the method name makes an accidental
    reorder visible without relying on a particular generated-Java spelling.
    """
    transactions = {}
    for filename, contract in sorted(files.items()):
        if not contract['kind'].endswith('interface'):
            continue
        methods = []
        for offset, declaration in enumerate(contract['declarations']):
            match = re.search(r'\b(' + IDENTIFIER + r')\s*\([^()]*\)\s*$', declaration)
            if match is None:
                raise ValueError('Unrecognized Binder method: ' + filename)
            methods.append({'method': match[1], 'offset': offset})
        transactions[contract['package'] + '.' + Path(filename).stem] = methods
    return transactions


def _matching_brace(source, opening, label):
    depth = 1
    position = opening + 1
    while position < len(source):
        if source[position] in ('"', "'"):
            position = quoted_end(source, position)
            continue
        if source[position] == '{':
            depth += 1
        elif source[position] == '}':
            depth -= 1
            if depth == 0:
                return position
        position += 1
    raise ValueError('Unterminated Kotlin declaration: ' + label)


def _kotlin_descriptor(value):
    nullable = value.endswith('?')
    base = value[:-1] if nullable else value
    types = {
        'Any': 'Ljava/lang/Object;',
        'Boolean': 'Z',
        'Byte': 'B',
        'Char': 'C',
        'Double': 'D',
        'Float': 'F',
        'Int': 'I',
        'Long': 'J',
        'Short': 'S',
        'String': 'Ljava/lang/String;',
        'Throwable': 'Ljava/lang/Throwable;',
        'Unit': 'V',
    }
    if base not in types or nullable and len(types[base]) == 1:
        raise ValueError('Unmodeled public Kotlin type: ' + value)
    return types[base]


def desktop_failure_contract(source, name='DesktopFailure'):
    """Project the deliberately tiny Kotlin helper onto its public JVM ABI."""
    source = without_comments(source)
    header = re.match(r'\s*package\s+(' + QUALIFIED +
                      r')\s+object\s+' + re.escape(name) + r'\s*\{', source)
    if header is None:
        raise ValueError('Unrecognized DesktopFailure declaration')
    position = header.end()
    declarations = []
    while True:
        position = skip_space(source, position)
        if position >= len(source):
            raise ValueError('Unterminated DesktopFailure object')
        if source[position] == '}':
            if source[position + 1:].strip():
                raise ValueError('Unexpected trailing DesktopFailure syntax')
            break
        opening = source.find('{', position)
        if opening < 0:
            raise ValueError('Unterminated DesktopFailure member')
        declaration = normalize(source[position:opening])
        method = re.fullmatch(r'fun\s+(' + IDENTIFIER + r')\s*\((.*?)\)\s*:\s*(' +
                              QUALIFIED + r'\??)', declaration)
        if method is None:
            raise ValueError('Unmodeled public DesktopFailure member: ' + declaration)
        parameters = []
        if method[2].strip():
            for parameter in method[2].split(','):
                item = re.fullmatch(r'\s*' + IDENTIFIER + r'\s*:\s*(' + QUALIFIED + r'\??)\s*',
                                    parameter)
                if item is None:
                    raise ValueError('Unmodeled DesktopFailure parameter: ' + parameter)
                parameters.append(_kotlin_descriptor(item[1]))
        declarations.append({'kind': 'method', 'name': method[1],
                             'descriptor': '(' + ''.join(parameters) + ')' +
                                           _kotlin_descriptor(method[3])})
        position = _matching_brace(source, opening, 'DesktopFailure.' + method[1]) + 1
    if not declarations:
        raise ValueError('DesktopFailure has no public declarations')
    return {'package': header[1], 'kind': 'object', 'declarations': declarations}


def kotlin_contract(sdk):
    root = sdk / 'src/main/kotlin/org/wonad/desktop/api'
    paths = sorted(root.glob('*.kt'))
    names = [path.name for path in paths]
    if names not in (['DesktopFailure.kt', 'DesktopProtocol.kt'],
                     ['DesktopFailure.kt', 'DesktopProtocol.kt', 'DesktopShortcutKeys.kt']) or any(
            path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError('Unexpected public Kotlin source set: ' + repr(names))
    return {path.name: desktop_failure_contract(path.read_text(), path.stem)
            for path in paths if path.stem != 'DesktopProtocol'}


def validate_source_jvm_consistency(kotlin_api, jvm_abi):
    if (not isinstance(jvm_abi, dict) or jvm_abi.get('schema') != 1 or
            not isinstance(jvm_abi.get('class_files'), list) or
            not isinstance(jvm_abi.get('classes'), dict)):
        raise ValueError('Invalid JVM ABI ledger')
    for filename, contract in kotlin_api.items():
        name = contract['package'].replace('.', '/') + '/' + Path(filename).stem
        public_class = jvm_abi['classes'].get(name)
        if not isinstance(public_class, dict):
            raise ValueError('Public Kotlin class missing from JVM ABI: ' + name)
        actual = {(row.get('name'), row.get('descriptor'))
                  for row in public_class.get('methods', [])}
        for declaration in contract['declarations']:
            expected = (declaration['name'], declaration['descriptor'])
            if expected not in actual:
                raise ValueError('Kotlin declaration missing from JVM ABI: ' + str(expected))


def signature_hash(aidl, constants, transactions, kotlin_api, jvm_abi):
    canonical = json.dumps({'aidl': aidl, 'constants': constants,
                            'binder_transactions': transactions,
                            'kotlin_api': kotlin_api, 'jvm_abi': jvm_abi},
                           sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def snapshot(sdk, jvm_abi=None):
    aidl = sdk / 'src/main/aidl/org/wonad/desktop/api'
    files = {}
    for path in sorted(aidl.glob('*.aidl')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Nonregular AIDL source: ' + str(path))
        source = without_comments(path.read_text())
        # Ordered declarations preserve Binder transaction numbers and the
        # structured-parcel field layout, including types/direction/nullability.
        files[path.name] = aidl_contract(source, path.stem)
    if not files:
        raise ValueError('SDK has no AIDL declarations')
    protocol = without_comments((sdk / 'src/main/kotlin/org/wonad/desktop/api/DesktopProtocol.kt').read_text())
    constants = protocol_constants(protocol)
    if constants.get('API_VERSION') != '3' or 'NATIVE_API_VERSION' in constants:
        raise ValueError('Expected the sole API3 endpoint')
    transactions = binder_transactions(files)
    kotlin_api = kotlin_contract(sdk)
    if jvm_abi is None:
        baseline = json.loads(BASELINE.read_text())
        jvm_abi = baseline.get('jvm_abi')
    validate_source_jvm_consistency(kotlin_api, jvm_abi)
    return {'schema': 3, 'scope': 'source_and_published_jvm_compatibility_not_runtime_qualification',
            'aidl': files, 'binder_transactions': transactions,
            'constants': constants, 'kotlin_api': kotlin_api, 'jvm_abi': jvm_abi,
            'signature_sha256': signature_hash(files, constants, transactions,
                                               kotlin_api, jvm_abi)}


def audit(actual, baseline):
    errors = []
    if actual.get('schema') != baseline.get('schema') or actual.get('scope') != baseline.get('scope'):
        errors.append('contract format/scope changed')
    if actual.get('aidl') != baseline.get('aidl'):
        for name in sorted(set(actual.get('aidl', {})) | set(baseline.get('aidl', {}))):
            if actual.get('aidl', {}).get(name) != baseline.get('aidl', {}).get(name):
                errors.append('review required for ordered wire declarations: ' + name)
    if actual.get('binder_transactions') != baseline.get('binder_transactions'):
        errors.append('review required for generated Binder transaction map')
    if actual.get('constants') != baseline.get('constants'):
        for name in sorted(set(actual.get('constants', {})) | set(baseline.get('constants', {}))):
            if actual.get('constants', {}).get(name) != baseline.get('constants', {}).get(name):
                errors.append('review required for SDK constant: ' + name)
    if actual.get('kotlin_api') != baseline.get('kotlin_api'):
        errors.append('review required for public Kotlin API')
    if actual.get('jvm_abi') != baseline.get('jvm_abi'):
        errors.append('review required for compiled public JVM ABI')
    if actual.get('signature_sha256') != baseline.get('signature_sha256'):
        errors.append('review required for API signature hash')
    return errors


def audit_additive(actual, previous):
    """An extension may append operations/types, never reinterpret old wire/JVM."""
    errors = []
    for name, old in previous['aidl'].items():
        new = actual['aidl'].get(name)
        if not isinstance(new, dict):
            errors.append('Removed AIDL type: ' + name); continue
        for key, value in old.items():
            if key in ('declarations', 'imports') and old.get('kind') == 'interface':
                if new.get(key, [])[:len(value)] != value:
                    errors.append('Changed legacy interface ' + key + ': ' + name)
            elif new.get(key) != value:
                errors.append('Changed legacy AIDL ' + key + ': ' + name)
    for name, value in previous['constants'].items():
        if actual['constants'].get(name) != value:
            errors.append('Changed legacy constant: ' + name)
    for name, value in previous['kotlin_api'].items():
        if actual['kotlin_api'].get(name) != value:
            errors.append('Changed legacy Kotlin API: ' + name)
    for name, rows in previous['binder_transactions'].items():
        if actual['binder_transactions'].get(name, [])[:len(rows)] != rows:
            errors.append('Renumbered legacy Binder transactions: ' + name)
    for name, old in previous['jvm_abi']['classes'].items():
        new = actual['jvm_abi']['classes'].get(name, {})
        for key, value in old.items():
            if key in ('methods', 'fields'):
                if any(row not in new.get(key, []) for row in value):
                    errors.append('Removed/changed legacy JVM member: ' + name)
            elif new.get(key) != value:
                errors.append('Changed legacy JVM type: ' + name)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, default=ANDROID / 'desktop-sdk')
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    parser.add_argument('--classes-jar', type=Path,
                        help='derive the public JVM ABI from this compiled classes.jar')
    parser.add_argument('--describe', action='store_true', help='Print current contract; never writes a baseline')
    args = parser.parse_args()
    try:
        if args.baseline.is_symlink():
            raise ValueError('Symlinked contract baseline')
        baseline = json.loads(args.baseline.read_text())
        if args.describe and args.classes_jar is None:
            raise ValueError('--describe requires --classes-jar; never recycle a baseline ledger')
        compiled = jvm_abi_from_jar(args.classes_jar) if args.classes_jar is not None else baseline.get('jvm_abi')
        actual = snapshot(args.sdk, compiled)
        if args.describe:
            print(json.dumps(actual, indent=2, sort_keys=True))
            return 0
        errors = audit(actual, baseline)
        print(json.dumps({'sdk_contract': 'not_passed' if errors else 'passed',
                          'scope': actual['scope'], 'errors': errors}, indent=2))
        return int(bool(errors))
    except (OSError, ValueError) as error:
        print(json.dumps({'sdk_contract': 'not_passed', 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
