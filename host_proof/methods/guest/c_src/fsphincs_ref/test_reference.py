#!/usr/bin/env python3
"""Independent v3-verifier/v4-leaf-PRF KAT checks, including unchanged node seeds."""
import argparse
import hashlib
from pathlib import Path
import sys

SETS = {"128s": (128, 0, 16, 22), "128f": (128, 1, 12, 61),
        "192s": (192, 0, 16, 33), "192f": (192, 1, 12, 92),
        "256s": (256, 0, 16, 43), "256f": (256, 1, 12, 120)}

# Pin the pre-optimization node-PRF outputs; changing leaf encoding must not change them.
V3_ROOT_SEEDS = {
    "128s": "a26b81c7ea9b0e19f278682ec1945b2bd224091542243e1ec91b4097db69864b",
    "128f": "eb6d5d5b8400e6292eff4eb6e6e2d95e898e950361d6915561b6b889c42c1e12",
    "192s": "7d5a4fd513b38ca8898d4a0ed17d7c3acd199a06a2d429847a00025b62758b14",
    "192f": "1c6c9a9ba89d2b102e35d143a061a76b90a2afc37b065a185e260829a6518411",
    "256s": "9200b551195fec2c01daaeaeab946090fc40ae4afaba2fdb8c29518ff63c582b",
    "256f": "3eae239c6517f00367b8ef895f013585b0a82e0b733b4b205ac1f7bbe4e1718b",
}

def main():
    """Verify every layer and certificate before checking committed fingerprints."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--params", required=True, choices=SETS)
    parser.add_argument("--emit", action="store_true",
                        help="Print independently verified fingerprints for review; does not update files")
    args = parser.parse_args()
    fields = dict(line.rstrip().split("=", 1) for line in sys.stdin if "=" in line)
    sec, fast, d, k = SETS[args.params]
    assert fields["parameter"] == args.params
    assert fields["kat_leaf_prf_version"] == "4"
    assert fields["kat_root_seed"] == V3_ROOT_SEEDS[args.params]
    n, h, q = 32, 6, 1024
    bits, m = k*d, (k*d+7)//8
    agg = 1 << (k-1).bit_length()
    anchors = 1 if sec == 128 else 2
    pk, sk, sig, msg, cert, root_seed, addresses, endpoints = (
        bytes.fromhex(fields["fixture_"+name]) for name in
        ("pk", "sk", "sig", "message", "certificate", "root_seed", "addresses", "anchors"))
    sha = lambda data: hashlib.sha256(data).digest()
    hx = hashlib.sha512 if sec == 256 else hashlib.sha256
    pub, root = pk[:32], pk[32:]
    R = sig[:32]

    def addr(domain, layer=0, node=0, tree=0, height=0, index=0):
        """Encode the public addressed-hash domain independently from C."""
        return bytes([domain, 3, sec >> 8, sec & 255]) + layer.to_bytes(4, "big") + \
            node.to_bytes(8, "big") + tree.to_bytes(4, "big") + \
            height.to_bytes(4, "big") + index.to_bytes(4, "big") + bytes([fast, d, k, 10])

    def canonical(data):
        """Zero unused low bits without losing the following H3 index bits."""
        out = bytearray(data[:m])
        if bits % 8:
            out[-1] &= 255 << (8 - bits % 8) & 255
        return bytes(out)

    def leaf_addr(layer=0, node=0, tree=0, index=0):
        """Encode only the leaf PRF in 16 bytes; other hash addresses stay v3."""
        assert 0 <= layer <= h and 0 <= node < q**layer
        assert 0 <= tree < k and 0 <= index < 2**d
        parameter_id = (sec//64-2)*2+fast
        return bytes([2, 4, parameter_id, layer]) + node.to_bytes(8, "big") + \
            bytes([tree]) + index.to_bytes(2, "big") + b"\x00"

    def h3(message, randomizer=R, public_key=pk):
        """Use the entire SHA-X digest, R and public key at both H3 stages."""
        context = bytes([7, 3, sec >> 8, sec & 255, fast, d, k, h, 10])
        prehash = hx(context + randomizer + public_key + message).digest()
        prefix = bytes([8]) + context[1:] + randomizer + public_key + prehash
        needed = (bits+60+7)//8
        expanded = b"".join(hx(prefix+i.to_bytes(4, "big")).digest()
                            for i in range((needed+hx().digest_size-1)//hx().digest_size))[:needed]
        stream = "".join(f"{b:08b}" for b in expanded)
        return canonical(expanded), int(stream[bits:bits+60], 2)

    def indices(md):
        """Slice exactly d bits, rather than interpreting each index as 16 bits."""
        stream = "".join(f"{b:08b}" for b in md)
        return [int(stream[i*d:(i+1)*d], 2) for i in range(k)]

    def parent(left, right, layer, node, tree, height, index):
        """Hash one addressed binary-tree edge."""
        return sha(pub + addr(4, layer, node, tree, height, index) + left + right)

    def recover(secret, path, target, layer, node, tree):
        """Authenticate one disclosed leaf secret through its inner M-FORS path."""
        value = sha(pub + addr(3, layer, node, tree, 0, target) + secret)
        for height in range(1, d+1):
            sibling = path[(height-1)*32:height*32]
            left, right = (sibling, value) if target & 1 else (value, sibling)
            target >>= 1
            value = parent(left, right, layer, node, tree, height, target)
        return value

    def h2(value, layer, node):
        """Map an aggregation root to its canonical k*d-bit public value."""
        a = addr(6, layer, node, k)
        seed = sha(pub+a+value)
        return canonical(b"".join(sha(bytes([6])+seed+a+i.to_bytes(4, "big"))
                                  for i in range((m+31)//32)))

    assert len(pk) == 32+m and len(sk) == 64+m and sk[32:] == pk
    assert len(sig) == 32+7*k*(d+1)*32
    md, node = h3(msg)
    assert node == int(fields["kat_index"])
    original_node = node
    offset = 32
    for step in range(7):
        layer = 6-step
        node_seed = sha(sk[:32]+addr(1, layer, node))
        roots = []
        for tree, target in enumerate(indices(md)):
            fragment = sig[offset:offset+(d+1)*32]
            assert fragment[:32] == sha(node_seed+leaf_addr(layer, node, tree, target))
            offset += len(fragment)
            roots.append(recover(fragment[:32], fragment[32:], target, layer, node, tree))
        roots += [sha(pub+addr(5, layer, node, i)) for i in range(k, agg)]
        height = 0
        while len(roots) > 1:
            height += 1
            roots = [parent(roots[2*i], roots[2*i+1], layer, node, k, height, i)
                     for i in range(len(roots)//2)]
        md = h2(roots[0], layer, node)
        assert sha(md).hex() == fields[f"kat_layer_{step}"]
        node //= q
    assert md == root and offset == len(sig)
    assert root_seed == sha(sk[:32]+addr(1))
    header = b"DAAFROOT"+bytes([4, 3, sec >> 8, sec & 255, fast, d, k, anchors])
    assert cert[:16] == header
    assert len(addresses) == anchors*16 and len(endpoints) == anchors*32
    roots = []
    offset = 16
    for tree in range(anchors):
        a = leaf_addr(tree=tree)
        assert addresses[tree*16:(tree+1)*16] == a
        assert len(root_seed+a) == 48
        secret = cert[offset:offset+32]
        assert secret == sha(root_seed+a) == endpoints[tree*32:(tree+1)*32]
        roots.append(recover(secret, cert[offset+32:offset+(d+1)*32], 0, 0, 0, tree))
        offset += (d+1)*32
    height = 1 if anchors == 2 else 0
    value = parent(roots[0], roots[1], 0, 0, k, 1, 0) if anchors == 2 else roots[0]
    while height < (agg.bit_length()-1):
        height += 1
        value = parent(value, cert[offset:offset+32], 0, 0, k, height, 0)
        offset += 32
    assert offset == len(cert) and h2(value, 0, 0) == root

    testmsg = bytes((i*37) & 255 for i in range(257))
    for length in (0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 257):
        md, index = h3(testmsg[:length])
        assert md.hex() == fields[f"h3_{length}"] and index == int(fields[f"index_{length}"])
    assert fields["parsed_indices"] == "".join(f"{i}," for i in indices(testmsg[:m]))
    assert h3(msg, bytes([R[0]^1])+R[1:]) != h3(msg)
    assert h3(msg, R, bytes([pk[0]^1])+pk[1:]) != h3(msg)
    assert original_node < 2**60
    for label, data in (("pk", pk), ("sk", sk), ("signature", sig), ("certificate", cert),
                        ("root_seed", root_seed), ("anchors", endpoints), ("addresses", addresses)):
        assert fields["kat_"+label] == sha(data).hex()
    manifest = "\n".join(f"{key}={value}" for key, value in fields.items()
                         if key == "parameter" or key.startswith("kat_"))+"\n"
    if args.emit:
        print(manifest, end="")
        print("independent_reference=ok", file=sys.stderr)
    else:
        expected = Path(__file__).with_name("kat") / (args.params+".txt")
        assert manifest == expected.read_text(), "KAT changed; investigate before replacing vectors"
        print(f"deterministic KAT {args.params}: ok; independent H3/layers/certificate/index checks: ok")

if __name__ == "__main__":
    main()
