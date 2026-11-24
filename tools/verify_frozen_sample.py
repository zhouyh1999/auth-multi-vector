"""Read-only independent arithmetic and search cross-check for frozen LoTTE query 2857."""
import argparse
import hashlib
import heapq
import json
from pathlib import Path
import struct

import numpy as np


RUN = Path(__file__).resolve().parents[1] / "tests/fixtures/lotte"
FIXTURE = RUN / "2857"
U32 = struct.Struct("<I")
U64 = struct.Struct("<Q")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(tag, value):
    return hashlib.sha256(U64.pack(len(tag)) + tag + U64.pack(len(value)) + value).digest()


def read_json(path):
    return json.loads(path.read_bytes())


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def take(self, length):
        end = self.pos + length
        require(end <= len(self.data), "truncated frozen input")
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "little")

    def entries(self, count):
        result = []
        for _ in range(count):
            flag = self.integer(1)
            require(flag in (0, 1), "invalid entry flag")
            result.append(self.integer(4) if flag else None)
        return result


def fixed(matrix):
    require(np.isfinite(matrix).all() and np.max(np.abs(matrix)) <= 1, "coordinate outside profile")
    return np.floor(matrix.astype(np.float64) * 32767).astype("<i2")


def public_packet(name):
    published = read_json(RUN / "publication.json")
    data = (RUN / "public" / name).read_bytes()
    require({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            == published["packets"][name], name)
    return data


def frozen_books(snapshot, trusted):
    manifest = read_json(RUN / "run-manifest.json")
    published = read_json(RUN / "publication.json")
    require(hashlib.sha256(trusted.read_bytes()).hexdigest() ==
            read_json(RUN / "input-receipts.json")["trusted.json"]["sha256"], "wrong source manifest")
    source = read_json(trusted)["signed"]["manifest"]
    base = source["source"]["manifest"]
    require(hashlib.sha256((RUN / "publication.json").read_bytes()).hexdigest() ==
            manifest["sources_and_inputs"]["publication.json"], "wrong publication")

    # A frozen EAuth occupies 269 bytes, including its length-prefixed signature.
    trusted_bytes = public_packet("raw.all.bin")[:-(8 + 3 * 269)]
    with snapshot.open("rb") as handle:
        prefix = handle.read(12 << 20)
    require(prefix.count(trusted_bytes) == 1, "source snapshot header mismatch")
    reader = Reader(prefix)
    reader.pos = prefix.index(trusted_bytes) + len(trusted_bytes)
    books = {}
    roots = {}
    for label, dtype in [("fine", "<f2"), ("coarse", "<f4")]:
        count = reader.integer(8)
        rows = base[label + "_count"]
        require(count == rows * 128, "book dimensions")
        raw = reader.take(count * np.dtype(dtype).itemsize)
        require(digest(f"gem.auth.v3.{label}.1".encode(), U64.pack(count) + raw) ==
                bytes(base[label + "_digest"]), "source book digest")
        book = np.frombuffer(raw, dtype=dtype).reshape(rows, 128)
        material = struct.pack("<IQQ", 0, rows, count) + fixed(book).tobytes() + U64.pack(0) * 3
        root = digest(b"four-method.material.v1", material)
        stage = public_packet(f"raw.{label}.bin")[-269:-72]
        require(stage[-33:-1] == root and digest(b"four-method.snapshot.v1", stage).hex() ==
                published["methods"]["raw"]["stages"][int(label == "fine")], "Raw stage root")
        books[label] = book
        roots[label] = root.hex()
    start = reader.pos
    count = reader.integer(8)
    require(count == base["coarse_count"], "entry count")
    entries = reader.entries(count)
    entry_hash = digest(b"gem.auth.v3.entries.9", prefix[start:reader.pos])
    require(entry_hash == bytes(source["entries_digest"]), "entry digest")
    return books, entries, dict(roots=roots, entry_hash=entry_hash.hex(), clusters=count,
                                missing=entries.count(None), distinct=len(set(entries) - {None}))


def fixture_data(path, books, entries):
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == read_json(FIXTURE / "reference.json")["source_vo_sha256"],
            "wrong historical source fixture")
    reader = Reader(data)
    require(bytes(reader.take(10)) == b"G3SBEN01\x09\x00" and reader.integer(8) == len(data) - 18,
            "wrong historical frame")
    require(bytes(reader.take(3)) == b"\x00\x00\x01", "expected cold FP16 fixture")
    require(reader.entries(len(entries)) == entries and reader.integer(1) == 1, "fixture entries")
    for key in ("fine", "coarse"):
        require(reader.take(books[key].nbytes) == books[key].tobytes(), "fixture book")

    def opening(dtype, size=None):
        flag = reader.integer(1)
        require(flag in (0, 1), "invalid component flag")
        if flag == 0:
            return None, bytes(reader.take(32))
        length = reader.integer(4) if size is None else size
        value = reader.take(length * np.dtype(dtype).itemsize)
        return np.frombuffer(value, dtype=dtype), U64.pack(length) + value

    docs, leaves = {}, {}
    for _ in range(reader.integer(4)):
        doc = reader.integer(4)
        rows = reader.integer(2)
        metadata = struct.pack("<IH", doc, rows)
        require(not docs or doc > next(reversed(docs)), "fixture document order")
        require(0 < rows <= 180, "fixture document length")
        fields = (opening("<u4"), opening("<u4", rows), opening("<u4"), opening("<f2", rows * 128))
        docs[doc] = tuple(value for value, _ in fields)
        schema = struct.pack("<H", 2)
        components = [digest(b"gem.auth.v3.component.2", schema + b"\0" + metadata * 2)]
        for kind, (value, encoded) in enumerate(fields, start=1):
            components.append(encoded if value is None else digest(
                b"gem.auth.v3.component.2", schema + bytes([kind]) + metadata + encoded))
        leaves[doc] = digest(b"gem.auth.v3.leaf.2", schema + b"".join(components))
    siblings = [bytes(reader.take(32)) for _ in range(reader.integer(4))]
    require(bytes(reader.take(2)) == b"\x00\x00", "unexpected historical proof layout")
    answers = []
    for _ in range(reader.integer(4)):
        doc = reader.integer(4)
        answers.append((int.from_bytes(reader.take(16), "little", signed=True), doc))
    require(reader.pos == len(data), "historical frame length")
    return docs, answers, leaves, siblings


def verify_multiproof(leaves, siblings, count, root):
    require(bool(leaves) and all(0 <= doc < count for doc in leaves), "Merkle opening bounds")
    remaining = iter(siblings)
    row = dict(sorted(leaves.items()))
    for _ in range((count - 1).bit_length()):
        next_row = {}
        for position, current in row.items():
            parent, side = divmod(position, 2)
            if parent in next_row:
                continue
            other = row.get(position ^ 1)
            if other is None:
                other = next(remaining, None)
                require(other is not None and len(other) == 32, "missing Merkle sibling")
            pair = other + current if side else current + other
            next_row[parent] = digest(b"gem.auth.v3.node.1", U32.pack(count) + pair)
        row = next_row
    require(row == {0: root} and next(remaining, None) is None, "Merkle root or surplus proof")


def read_tree_proof(handle, ids, count):
    require(handle.read(4) == U32.pack(count), "tree document count")
    height = (count - 1).bit_length()
    require(handle.read(8) == U64.pack(height + 1), "tree height")
    siblings = []
    positions = sorted(ids)
    for level in range(height):
        width = 1 << (height - level)
        require(handle.read(8) == U64.pack(width), "tree level width")
        start = handle.tell()
        present = set(positions)
        for sibling in sorted(position ^ 1 for position in positions if (position ^ 1) not in present):
            handle.seek(start + sibling * 32)
            value = handle.read(32)
            require(len(value) == 32, "truncated tree level")
            siblings.append(value)
        handle.seek(start + width * 32)
        positions = sorted({position // 2 for position in positions})
    return siblings


def verify_raw_rerank(docs, candidates, count, siblings):
    leaves = {}
    for doc in candidates:
        raw = fixed(docs[doc][3])
        require(raw.size != 0 and raw.size % 128 == 0, "invalid raw candidate shape")
        material = struct.pack("<IQQ", doc, raw.size // 128, raw.size)
        leaves[doc] = digest(b"four-method.material.v1", material + raw.tobytes() + U64.pack(0) * 3)
    published = read_json(RUN / "publication.json")
    stage = public_packet("raw.rerank.bin")[-269:-72]
    require(digest(b"four-method.snapshot.v1", stage).hex() ==
            published["methods"]["raw"]["stages"][2], "Raw rerank stage digest")
    root = stage[-33:-1]
    verify_multiproof(leaves, siblings, count, root)
    return dict(root=root.hex(), documents=len(leaves), siblings=len(siblings))


def replay(query, books, entries, docs):
    q = fixed(query).astype(np.int64)

    def table(matrix):
        values = q @ fixed(matrix).astype(np.int64).T
        require(values.min() >= -(1 << 31) and values.max() < 1 << 31, "dot outside i32")
        return values

    coarse = table(books["coarse"])
    selected = sorted(set(np.argsort(-coarse, axis=1, kind="stable")[:, :4].ravel().tolist()))
    fine = table(books["fine"])
    cluster_set = set(selected)
    constant = 32 * 32767**2

    def node(doc):
        return constant - int(fine[:, docs[doc][1]].max(axis=1).sum()), doc

    owners = {}
    for cluster in selected:
        if entries[cluster] is not None:
            owners.setdefault(entries[cluster], cluster)
    starts = sorted((c, d) for d, c in owners.items())
    compared, expanded, examined, pruned, stops = [], [], [], [], []
    visited = set(owners)
    queues, retained = [], []
    for cluster, doc in starts:
        require(cluster in docs[doc][0], "entry membership")
        dist, _ = node(doc)
        compared.append((dist, doc))
        queues.append([(dist, doc)])
        heapq.heappush(retained, (-dist, -doc))
    epoch = 0
    while True:
        popped = False
        for (cluster, entry), queue in zip(starts, queues):
            if not queue:
                continue
            dist, current = queue[0]
            threshold = -retained[0][0]
            if dist > threshold:
                stops.append((epoch, cluster, entry, current, dist, threshold))
                queue.clear()
                continue
            heapq.heappop(queue)
            popped = True
            expanded.append(current)
            for neighbor in docs[current][2].tolist():
                examined.append(neighbor)
                if cluster_set.isdisjoint(docs[neighbor][0]):
                    pruned.append(neighbor)
                    continue
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                value = node(neighbor)
                compared.append(value)
                if len(retained) < 1024 or value[0] < -retained[0][0]:
                    heapq.heappush(queue, value)
                    heapq.heappush(retained, (-value[0], -neighbor))
                    if len(retained) > 1024:
                        heapq.heappop(retained)
        if not popped:
            break
        epoch += 1
    retained = sorted((-dist, -doc) for dist, doc in retained)
    candidates = retained[:1024]
    ranking = sorted((constant - int(table(docs[doc][3].reshape(-1, 128)).max(axis=1).sum()), doc)
                     for _, doc in candidates)[:100]

    # Serialize independent trace and read sets in the frozen bincode field order.
    def vector(items, pack):
        return U64.pack(len(items)) + b"".join(pack(item) for item in items)

    def signed(value):
        return value.to_bytes(16, "little", signed=True)

    def pack_node(item):
        return U32.pack(item[1]) + signed(item[0])

    def pack_stop(item):
        return struct.pack("<IIII", *item[:4]) + signed(item[4]) + signed(item[5])

    trace = (vector(selected, U32.pack) + vector(starts, lambda pair: struct.pack("<II", *pair)) +
             vector(compared, pack_node) + vector(expanded, U32.pack) + vector(examined, U32.pack) +
             vector(pruned, U32.pack) + vector(retained, pack_node) + vector(candidates, pack_node) +
             vector(stops, pack_stop))
    candidate_ids = sorted(doc for _, doc in candidates)
    usage = b"".join(vector(sorted(ids), U32.pack) for ids in
                     (set(owners) | set(examined), visited, set(expanded), candidate_ids))
    execution = digest(b"gem.csr38.execution-and-results.v1", trace + usage + vector(ranking, pack_node))
    def matrix_digest(matrices):
        payload = bytearray(U64.pack(len(matrices)))
        for doc, scores in matrices:
            payload.extend(struct.pack("<IQQ", doc, scores.shape[1], scores.size))
            payload.extend(scores.astype("<i4").tobytes())
        return digest(b"four-method.stage-verified-matrices.v1", payload).hex()

    stages = [matrix_digest([(0, coarse)]), matrix_digest([(0, fine)]),
              matrix_digest([(doc, table(docs[doc][3].reshape(-1,128))) for doc in candidate_ids])]
    return ranking, candidate_ids, dict(stage_digests=stages, execution=execution.hex(), selected=len(selected),
                                        queues=len(starts), comparisons=len(compared), expanded=len(expanded),
                                        examined=len(examined), stops=len(stops))


def fp32_comparison(query, docs, candidates, ranking):
    # Keep the candidate set fixed to measure only the effect of the scoring rules.
    scores = []
    for doc in candidates:
        rows = docs[doc][3].reshape(-1, 128).astype(np.float32)
        dots = np.zeros((len(query), len(rows)), dtype=np.float32)
        for column in range(128):
            dots += query[:, column, None] * rows[:, column]
        distance = np.float32(0)
        for similarity in dots.max(axis=1):
            distance += np.float32(1) - similarity
        scores.append((distance / np.float32(len(query)), doc))
    top = sorted(scores)[:100]
    return dict(changed_positions=sum(a[1] != b[1] for a, b in zip(top, ranking)),
                fp32_first_distance=float(top[0][0]), fixed_first_distance=ranking[0][0],
                fixed_first_id=ranking[0][1])


def read_query(path, current):
    request = read_json(path)["query"]
    coords = np.array(request["coordinates"], dtype="<f4").reshape(32, 128)
    params = tuple(request["params"][key] for key in ("k", "rerank_k", "cluster_top_t", "ef_search"))
    header = struct.pack("<QHHQ", request["query_id"], request["dimension"], request["token_count"], coords.size)
    binding = digest(b"query", header + coords.tobytes() + struct.pack("<IIII", *params)).hex()
    require(params == (100, 1024, 4, 1024) and binding == current["query_sha256"], "wrong query")
    return coords


def coarse_comparison(book, references):
    differences = []
    paths = sorted(FIXTURE.parent.glob("*/request.json"))
    fixed_book = fixed(book).astype(np.int64).T.copy()
    for path in paths:
        query_id = int(path.parent.name)
        query = read_query(path, references[query_id])
        dots = np.zeros((32, len(book)), dtype=np.float32)
        for column in range(128):
            dots += query[:, column, None] * book[:, column]
        integers = fixed(query).astype(np.int64) @ fixed_book
        fp_ids = np.argsort(-dots, axis=1, kind="stable")[:, :4]
        fixed_ids = np.argsort(-integers, axis=1, kind="stable")[:, :4]
        if set(fp_ids.ravel()) != set(fixed_ids.ravel()):
            changed = [dict(token=t, fp32=fp_ids[t].tolist(), fixed=fixed_ids[t].tolist())
                       for t in range(32) if set(fp_ids[t]) != set(fixed_ids[t])]
            differences.append(dict(query=query_id, changed=changed))
    return dict(queries=len(paths), different_unions=differences)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("offline_compact", type=Path)
    parser.add_argument("trusted_json", type=Path)
    parser.add_argument("source_vo_2857", type=Path)
    parser.add_argument("--raw-tree", type=Path, help="optionally verify all Raw candidates against the published rerank tree")
    parser.add_argument("--records", type=Path, help="q2857.jsonl from a 16-cell smoke plan")
    args = parser.parse_args()
    books, entries, book_stats = frozen_books(args.offline_compact, args.trusted_json)
    docs, historical, leaves, siblings = fixture_data(args.source_vo_2857, books, entries)
    source = read_json(args.trusted_json)["signed"]["manifest"]["source"]["manifest"]
    count, root = source["document_count"], bytes(source["document_root"])
    verify_multiproof(leaves, siblings, count, root)
    reference_bytes = (RUN / "native-reference.jsonl").read_bytes()
    require(hashlib.sha256(reference_bytes).hexdigest() == read_json(RUN / "records/full/identity.json")["native_reference"],
            "wrong current reference file")
    references = {row["query_id"]: row for row in map(json.loads, reference_bytes.splitlines())}
    current = references[2857]
    query = read_query(FIXTURE / "request.json", current)
    ranking, candidates, stats = replay(query, books, entries, docs)
    historical_ref = read_json(FIXTURE / "reference.json")
    require(ranking == historical and candidates == sorted(historical_ref["candidate_ids"]), "reference ranking or IDs")
    require(stats["execution"] == current["execution_digest"] == historical_ref["execution_digest"], "execution digest")
    if args.records:
        rows = [json.loads(line) for line in args.records.read_bytes().splitlines()]
        expected = dict(zip(("coarse","fine","rerank"),stats["stage_digests"]))
        expected["all"] = stats["execution"]
        seen = set()
        for row in rows:
            cell = (row["policy"],row["stage"])
            require(row["query_id"]==2857 and row["verified"] and cell not in seen, "record binding")
            require(row["execution_digest"]==expected[cell[1]], "independent matrix or search mismatch")
            seen.add(cell)
        require(seen == {(m,s) for m in ("raw","vida_per_token","vida_batched","block_fast") for s in expected},
                "incomplete smoke records")
        stats["new_smoke_cells_matched"] = len(seen)
    results = dict(**book_stats, **stats, candidates=len(candidates), results=len(ranking),
                   source_tree=dict(root=root.hex(), documents=len(leaves), siblings=len(siblings)),
                   fp32_fixed_candidates=fp32_comparison(query, docs, candidates, ranking),
                   coarse_comparison=coarse_comparison(books["coarse"], references))
    if args.raw_tree:
        with args.raw_tree.open("rb") as handle:
            raw_siblings = read_tree_proof(handle, candidates, count)
        results["raw_rerank_tree"] = verify_raw_rerank(docs, candidates, count, raw_siblings)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
