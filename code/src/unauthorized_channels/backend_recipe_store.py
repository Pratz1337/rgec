"""Host-only experimental authenticated recipe store, not certified admission."""
import hashlib
import hmac
import json
import os
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def packet_key(packet):
    if packet[:6] not in (b'RGECB1', b'RGECB2', b'RGECB3') or len(packet) < 14:
        raise ValueError('invalid native recipe frame')
    size = struct.unpack_from('<Q', packet, 6)[0]
    if size > len(packet) - 14:
        raise ValueError('truncated native recipe key')
    if packet[:6] in (b'RGECB1', b'RGECB3'):
        return packet[14:14 + size]
    offset = 14 + size
    if len(packet) - offset < 8:
        raise ValueError('truncated computation key')
    length = struct.unpack_from('<Q', packet, offset)[0]
    if length > len(packet) - offset - 8:
        raise ValueError('truncated computation key')
    return packet[offset + 8:offset + 8 + length]


def key_files(bound):
    offset = [0]
    def number():
        value = struct.unpack_from('<Q', bound, offset[0])[0]
        offset[0] += 8
        return value
    def field():
        size = number()
        value = bound[offset[0]:offset[0] + size]
        offset[0] += size
        if len(value) != size:
            raise ValueError('truncated compiler state')
        return value
    count = number()
    if count > 10000:
        raise ValueError('unsupported invocation size')
    for _ in range(count):
        field()
    field()  # Captured IR; the residual producer consumes it without ParseAST.
    count, _ = number(), number()
    if count > 1000000:
        raise ValueError('unsupported source map size')
    files = []
    for _ in range(1, count):
        number()
        if number():
            number(); number()
            files.append((field().decode(), field()))
        else:
            number(); number(); number(); number()
    if offset[0] != len(bound) and not (
            bound[offset[0]:offset[0] + 6] == b'RGECS3' and computation_key(bound)):
        raise ValueError('invalid compiler state trailing bytes')
    return files


def computation_key(bound, captured_reads=None):
    """Mirror the experimental native projection; not a closure certificate."""
    offset = [0]
    core = bytearray(b'RGECK1')
    def number():
        if len(bound) - offset[0] < 8:
            raise ValueError('truncated residual state')
        value = struct.unpack_from('<Q', bound, offset[0])[0]
        offset[0] += 8
        return value
    def field():
        size = number()
        if size > len(bound) - offset[0]:
            raise ValueError('truncated residual field')
        value = bound[offset[0]:offset[0] + size]
        offset[0] += size
        return value
    def put(value):
        core.extend(struct.pack('<Q', len(value))); core.extend(value)
    count = number()
    if count > 10000:
        raise ValueError('unsupported invocation size')
    core.extend(struct.pack('<Q', count))
    for _ in range(count): put(field())
    put(field())
    count = number(); number()
    if not 2 <= count <= 1000000:
        raise ValueError('unsupported source map size')
    files = []
    for _ in range(1, count):
        number(); file = bool(number()); files.append(file)
        number(); number()
        if file: field(); field()
        else: number(); number()
    if bound[offset[0]:offset[0] + 6] != b'RGECS3':
        raise ValueError('unsupported residual state')
    offset[0] += 6
    put(field()); number()
    for file in files:
        number()
        if file: number(); number()
    if number():
        names = number()
        if names > 1000000: raise ValueError('unsupported line table')
        for _ in range(names): field()
        entries = number()
        if entries > count: raise ValueError('unsupported line table')
        for _ in range(entries):
            number(); lines = number()
            if lines > 1000000: raise ValueError('unsupported line table')
            for _ in range(lines * 5): number()
    tail = offset[0]
    number(); number(); functions = number()
    if functions > 1000000: raise ValueError('unsupported function table')
    for _ in range(functions):
        field()
        if number(): number()
    if offset[0] != len(bound):
        if bound[offset[0]:offset[0] + 6] != b'RGECR1':
            raise ValueError('unsupported backend read state')
        offset[0] += 6
        reads = number()
        if not 1 <= reads <= 10000: raise ValueError('unsupported backend read count')
        for _ in range(reads):
            path, size, terminated, volatile = field(), number(), number(), number()
            if terminated > 1 or volatile > 1: raise ValueError('invalid backend read flags')
            identifier, contents = field(), field()
            if captured_reads is not None:
                captured_reads.append((path.decode(), contents))
    if offset[0] != len(bound): raise ValueError('invalid residual trailing bytes')
    core.extend(bound[tail:])
    return bytes(core)


class BackendRecipeStore:
    def __init__(self, context, producer):
        self.context = dict(context)
        self.producer = producer
        self.entries = {}
        self.audit = []
        self._secret = os.urandom(32)

    def _tag(self, receipt):
        body = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
        return hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def resolve(self, profile, bound):
        lookups = [('full-context', bound)]
        if self.context.get('protocol') in ('RGECB2', 'RGECB3'):
            lookups.insert(0, ('computation', computation_key(bound)))
        invalid_entry = False
        for binding, lookup in lookups:
            index = (profile, sha(lookup))
            entry = self.entries.get(index)
            if not entry:
                continue
            receipt, packet, tag = entry
            valid = (hmac.compare_digest(tag, self._tag(receipt)) and
                receipt['context'] == self.context and receipt['profile'] == profile and
                receipt['key_sha256'] == index[1] and receipt['packet_sha256'] == sha(packet))
            if valid:
                try:
                    valid = packet_key(packet) == lookup and (packet[:6] in (b'RGECB2', b'RGECB3')) == (binding == 'computation')
                except ValueError:
                    valid = False
            if valid:
                self.audit.append({'profile': profile, 'key_sha256': index[1],
                                   'binding': binding, 'route': 'authenticated-hit'})
                return packet
            invalid_entry = True
        # Invalid store data cannot supply an effect program to the recipient.
        packet, origin = self.producer(profile, bound)
        admitted = origin['reusable'] and origin['returncode'] in (0, 1)
        try:
            key = packet_key(packet)
            selected = next(((binding, lookup) for binding, lookup in lookups if key == lookup and
                (packet[:6] in (b'RGECB2', b'RGECB3')) == (binding == 'computation')), None)
        except ValueError:
            selected = None
        if not admitted or selected is None:
            self.audit.append({'profile': profile, 'key_sha256': sha(bound),
                               'route': 'native-fallback', 'origin': origin})
            return b''
        binding, lookup = selected
        if self.context.get('protocol') == 'RGECB3' and packet[:6] == b'RGECB2':
            # Provenance stays in the private receipt; delivery contains only
            # computation state and the unchanged native effect program.
            full_size = struct.unpack_from('<Q', packet, 6)[0]
            packet = b'RGECB3' + packet[14 + full_size:]
        index = (profile, sha(lookup))
        receipt = {'version': 1, 'context': self.context, 'profile': profile,
                   'binding': binding, 'key_sha256': index[1], 'packet_sha256': sha(packet), 'origin': origin,
                   'complete_closure_certified': False}
        self.entries[index] = (receipt, packet, self._tag(receipt))
        self.audit.append({'profile': profile, 'key_sha256': index[1],
                           'binding': binding,
                           'route': 'recomputed-invalid-entry' if invalid_entry else 'separate-producer-miss',
                           'origin': origin})
        return packet
