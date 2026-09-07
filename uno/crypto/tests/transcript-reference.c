#include <at/crypto/at_merlin.h>
#include <stdio.h>

int main(void) {
  at_merlin_transcript_t transcript;
  unsigned char message[1024], first[64], second[64];
  for (unsigned i = 0; i < sizeof(message); ++i) message[i] = (unsigned char)i;
  at_merlin_transcript_init(&transcript, AT_MERLIN_LITERAL("kernel-transcript-reference-v1"));
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL("message"), message, sizeof(message));
  at_merlin_transcript_append_u64(&transcript, AT_MERLIN_LITERAL("counter"), 0x0102030405060708UL);
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL("first"), first, sizeof(first));
  at_merlin_transcript_append_message(&transcript, AT_MERLIN_LITERAL("response"), first, sizeof(first));
  at_merlin_transcript_challenge_bytes(&transcript, AT_MERLIN_LITERAL("second"), second, sizeof(second));
  for (unsigned i = 0; i < sizeof(first); ++i) printf("%02x", first[i]);
  puts("");
  for (unsigned i = 0; i < sizeof(second); ++i) printf("%02x", second[i]);
  puts("");
  return ferror(stdout) ? 2 : 0;
}
