#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

void randombytes(unsigned char *out, size_t outlen) {
    (void)out;
    (void)outlen;
    abort();
}

#if FS_K == 35
static const char EXPECT_PK[] =
    "21f47631058e5d333b92a1f5c78c1cb868913cca60c896fad61e24166dc497eb";
static const char EXPECT_SK[] =
    "83d7f95000a512319996f430b433799eb5aa92003656944eb0ba39875894af28";
static const char EXPECT_SIG[] =
    "8e1f7d91aa7b75ae87d14124b252a98b9d92f5e6874894c8b4ce405551612e2a";
static const char *EXPECT_LAYER[FS_H + 1u] = {
    "f14a03c98b666f4a791666850be761903cbb7985dfb67a60d9065d462cd44042",
    "ce405d6a8c68731a22fc669b450e7b0f59914bee8ed18b719a768f4301c5fb1e",
    "5088a8ddd5d1efb8e3a7a3d78b95ce854e8f34ba436b3bb80c070b80f651e15e",
    "455d87f464e188a352cb1e36e8b2041afcd99616c8213f7bfc3c6ddd8fa59da2",
    "73fd53e4f0a47d2725adcc0e706f077a567ba18779f03a1a654522be0b768f51",
    "852b6aaa51768211aec10da2168268f3f39e076cca055247b7314bb423f30c3c",
    "87ec9636252b67e577868eccd64535c08dc358d445e9214a0a91d48527fcc6e8",
};
static const uint64_t EXPECT_INDEX = UINT64_C(373729149056017821);
#elif FS_K == 70
static const char EXPECT_PK[] =
    "b3c2df74bad3447d8a68eac61f97c24dc400d70fd0c86c2d92fe4004fb8df0f5";
static const char EXPECT_SK[] =
    "ce6739830f56fa2d5060f55e4156472069c4a79b0caa4dc0e13fd93e7456b2c8";
static const char EXPECT_SIG[] =
    "dd951a563c105ec742554dbd15b7599dc80ebe5513139df31afac519a85c2dba";
static const char *EXPECT_LAYER[FS_H + 1u] = {
    "2d4dbeaccf32c3280d61362aa41b834398c2516f83a14d915e1284213a4c46c1",
    "1a55e71ad9f8e84f0a53f659db76061504b641e28a6ce300b99013c04819daa2",
    "e4031bc5473d6d48fcf6bbc9d6a540112aee2f8297d810db88e3b37b5a2f93ed",
    "25052754c9749448228dd5f390f131ea793aa692c5903752eeac1a6e30498a9c",
    "ea0a3a894f602ad2e2e3a26cfe166f2afe5f3aca24d1a05b0120b4e19fdb6a72",
    "9e0a1d3e12b17f3913f9e95565d8f99fef80fb85b721adbc630a42e4c91f0d4a",
    "830d81c8ae5bfece63ddb64e7e5f7d572c108b6b173c2eca398409f881d93e30",
};
static const uint64_t EXPECT_INDEX = UINT64_C(273450963243707641);
#elif FS_K == 22
static const char EXPECT_PK[] =
    "34e1c4a8cfc1f5537dbde9c2d6aaf350ac4dde02b10bcfd4de1eb75f66765166";
static const char EXPECT_SK[] =
    "b1411aa38854fc2b431ad7c1a75a329850189ef8be6101aca81b37b2709bbbf0";
static const char EXPECT_SIG[] =
    "57b4232dc22ba2f76ad32d3f42df6121f1a35d17d1a050bff02df12a7e1d4dd6";
static const char *EXPECT_LAYER[FS_H + 1u] = {
    "3b479b9a2e99225dec4a5c1f6a7443b26138e3775b4533f6454dbd03a6a81f76",
    "e741969c3d40ab2d55d9b048cadc650a66ff9f9ea16076f91a7cc5c65cfff08d",
    "6ad17fd16da6d4a527d56f8b2b493ae49b41d095a9e3a37adab7e78d240eabac",
    "1b8e2b8f01ff150095db58bb874d808e3f27939ef85c0976050b56679de0151b",
    "0276b42b6abb0c28d8322d1e19d857837b000d137aa806d8bf4ada403160e757",
    "07652ace0748f3b669c9b82fea83e71f1bdee0a36f5bf0a3d1b9277216ec8584",
    "8840623fab800be62cfce42eca81c04ea7c03662863fc601861fea1a7fd43e77",
};
static const uint64_t EXPECT_INDEX = UINT64_C(971378804817579217);
#elif FS_K == 33
static const char EXPECT_PK[] =
    "cc7fc81b8149dca82229e5bcc1cc7d5ea18dcb94d77afde980412bc233218c73";
static const char EXPECT_SK[] =
    "9e937a2790df35c04aafcf3aa2ea4aeb1062fa9300b3db87a81c6b5a0e83d592";
static const char EXPECT_SIG[] =
    "1974561db939967ca99022a6af003075405cf4dd0e4a8d81a35379b521714e83";
static const char *EXPECT_LAYER[FS_H + 1u] = {
    "77899e0fdd752481a2b4d957aaeee6887ffac2132372aaa3392df9bd42c56678",
    "e99e4e77dbd966ee88ad21a0cdbf4c2b10f76e93bd0376fd1d3832eaaf092ef2",
    "ae165e1123fbf3e115cced8ce993187af2062a764734d3b5e991eca57a4f5634",
    "c8f47cbe33167991d2646229d2eeb97ca1697a606b0e938afa7bbf6f16acbb78",
    "0377f6cf794425c807b93ca782ac51c41b1f14e925898db38b6e3d6a9a3137e7",
    "a47fa6d6da4e2546a9575547cdd251c10d8f4b47ad2f5f2ccf6cbfef4fcef2e2",
    "a632f4cd49d0f9f4fbea2875359ca3473fa0048b0aa11834806a2338b677f46b",
};
static const uint64_t EXPECT_INDEX = UINT64_C(515896955498381486);
#else /* FS_K == 43 */
static const char EXPECT_PK[] =
    "a99d3bd7e135dd1343c62023dd3ad17ee4f7088c7a06859a2154d97f733faaea";
static const char EXPECT_SK[] =
    "92d8d06f181f9edd39dbceaff7b6c8067ae8d8b3148d3399f06ae33e34e94e0e";
static const char EXPECT_SIG[] =
    "0b764e1ba7f9ffec5930e675b878b01ece7de7ee88bea2214a8a517a04e989c8";
static const char *EXPECT_LAYER[FS_H + 1u] = {
    "9bd01a62dd391519aaa21750d6e909123570447552ed580f2d45ff859d7b9efc",
    "dff51f58162b3440db78ae1dee712fdbbcc3eb951f7be7e074e59861796d24a9",
    "d102dc8fea2ae70d53c14994bc8fdb01da86cc1a5532d74f291b8a237e46a241",
    "04510d3d03b16617d804f58319a89157a218d8a132c64e0330a7c86d3325936d",
    "494f9cb21288a9f3bf9acd74df889ed64170af6dc99a7e4a257327c2205a0ec1",
    "8d58ae11d57ce67fbbbe74fea91e0d00881156ed555dc81d7b064862a45abded",
    "5a8866b2407456fa83d18a5c3c7720ac3ec400dedee3ebf766306e22bda3bc9a",
};
static const uint64_t EXPECT_INDEX = UINT64_C(541964557103370514);
#endif

void SPX_u32_to_bytes(unsigned char *out, uint32_t in) {
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

static void hex_digest(char out[65], const uint8_t *data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32];
    sha256(digest, data, len);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 15];
    }
    out[64] = 0;
}

static int check(const char *label, const char *actual, const char *expected) {
    printf("%s = %s\n", label, actual);
    if (!expected[0]) return 0;
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s KAT mismatch\n", label);
        return -1;
    }
    return 0;
}

int main(void) {
    static const uint8_t message[] =
        "PQCrypto-2023 F-SPHINCS+-SHA256 deterministic KAT v1";
    uint8_t seed[FS_SEED_BYTES], randomizer[FS_N];
    uint8_t pk[FS_PK_BYTES], sk[FS_SK_BYTES];
    uint8_t *sig = malloc(FS_SIG_BYTES);
    uint8_t layers[(FS_H + 1u) * FS_MFORS_MSG_BYTES];
    size_t siglen = 0;
    uint64_t index = 0;
    char digest[65], label[32];
    int failed = 0;
    if (!sig) return 1;
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(randomizer); ++i)
        randomizer[i] = (uint8_t)(0xa0u + i);

    if (fsphincs_seed_keypair(pk, sk, seed) != 0) return 2;
    if (fsphincs_sign_signature_with_randomizer(
            sig, &siglen, message, sizeof(message) - 1, sk, randomizer) != 0)
        return 3;
    if (siglen != FS_SIG_BYTES) return 4;
    if (fsphincs_trace_signature(layers, &index, sig, siglen,
                                 message, sizeof(message) - 1, pk) != 0)
        return 5;

    hex_digest(digest, pk, sizeof(pk));
    failed |= check("pk_sha256", digest, EXPECT_PK);
    hex_digest(digest, sk, sizeof(sk));
    failed |= check("sk_sha256", digest, EXPECT_SK);
    hex_digest(digest, sig, siglen);
    failed |= check("signature_sha256", digest, EXPECT_SIG);
    printf("leaf_index = %llu\n", (unsigned long long)index);
    if (EXPECT_INDEX != 0 && index != EXPECT_INDEX) {
        fprintf(stderr, "leaf index KAT mismatch\n");
        failed = 1;
    }
    for (uint32_t i = 0; i <= FS_H; ++i) {
        hex_digest(digest, layers + (size_t)i * FS_MFORS_MSG_BYTES,
                   FS_MFORS_MSG_BYTES);
        snprintf(label, sizeof(label), "recovered_step_%u_sha256", i);
        failed |= check(label, digest, EXPECT_LAYER[i]);
    }
    free(sig);
    if (failed) return 6;
    printf("deterministic KAT: ok\n");
    return 0;
}
