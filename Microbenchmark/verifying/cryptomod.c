#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/slab.h>

#include <linux/ktime.h>
#include <linux/sort.h>
#include <linux/moduleparam.h>

#include "blake2-impl.h"
#include "blake2.h"

static int len= 256; //generating size
module_param(len,int,S_IRUGO);  
static unsigned long long my_time[320000];
#define iteration 200000

//region Blake2 functions
//---------------------------------------------------------------------------------------

static const uint64_t blake2b_IV[8] =
	{
		0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
		0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
		0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint8_t blake2b_sigma[12][16] =
	{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static void blake2b_set_lastnode(blake2b_state *S)
{
	S->f[1] = (uint64_t)-1;
}

/* Some helper functions, not necessarily useful */
static int blake2b_is_lastblock(const blake2b_state *S)
{
	return S->f[0] != 0;
}

static void blake2b_set_lastblock(blake2b_state *S)
{
	if (S->last_node)
		blake2b_set_lastnode(S);

	S->f[0] = (uint64_t)-1;
}

static void blake2b_increment_counter(blake2b_state *S, const uint64_t inc)
{
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static void blake2b_init0(blake2b_state *S)
{
	size_t i;
	memset(S, 0, sizeof(blake2b_state));

	for (i = 0; i < 8; ++i)
		S->h[i] = blake2b_IV[i];
}

/* init xors IV with input parameter block */
int blake2b_init_param(blake2b_state *S, const blake2b_param *P)
{
	const uint8_t *p = (const uint8_t *)(P);
	size_t i;

	blake2b_init0(S);

	/* IV XOR ParamBlock */
	for (i = 0; i < 8; ++i)
		S->h[i] ^= load64(p + sizeof(S->h[i]) * i);

	S->outlen = P->digest_length;
	return 0;
}

int blake2b_init(blake2b_state *S, size_t outlen)
{
	blake2b_param P[1];

	if ((!outlen) || (outlen > BLAKE2B_OUTBYTES))
		return -1;

	P->digest_length = (uint8_t)outlen;
	P->key_length = 0;
	P->fanout = 1;
	P->depth = 1;
	store32(&P->leaf_length, 0);
	store32(&P->node_offset, 0);
	store32(&P->xof_length, 0);
	P->node_depth = 0;
	P->inner_length = 0;
	memset(P->reserved, 0, sizeof(P->reserved));
	memset(P->salt, 0, sizeof(P->salt));
	memset(P->personal, 0, sizeof(P->personal));
	return blake2b_init_param(S, P);
}

int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen)
{
	blake2b_param P[1];

	if ((!outlen) || (outlen > BLAKE2B_OUTBYTES))
		return -1;

	if (!key || !keylen || keylen > BLAKE2B_KEYBYTES)
		return -1;

	P->digest_length = (uint8_t)outlen;
	P->key_length = (uint8_t)keylen;
	P->fanout = 1;
	P->depth = 1;
	store32(&P->leaf_length, 0);
	store32(&P->node_offset, 0);
	store32(&P->xof_length, 0);
	P->node_depth = 0;
	P->inner_length = 0;
	memset(P->reserved, 0, sizeof(P->reserved));
	memset(P->salt, 0, sizeof(P->salt));
	memset(P->personal, 0, sizeof(P->personal));

	if (blake2b_init_param(S, P) < 0)
		return -1;

	{
		uint8_t block[BLAKE2B_BLOCKBYTES];
		memset(block, 0, BLAKE2B_BLOCKBYTES);
		memcpy(block, key, keylen);
		blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
		secure_zero_memory(block, BLAKE2B_BLOCKBYTES); /* Burn the key from stack */
	}
	return 0;
}

#define G(r, i, a, b, c, d)                         \
	do {                                            \
		a = a + b + m[blake2b_sigma[r][2 * i + 0]]; \
		d = rotr64(d ^ a, 32);                      \
		c = c + d;                                  \
		b = rotr64(b ^ c, 24);                      \
		a = a + b + m[blake2b_sigma[r][2 * i + 1]]; \
		d = rotr64(d ^ a, 16);                      \
		c = c + d;                                  \
		b = rotr64(b ^ c, 63);                      \
	} while (0)

#define ROUND(r)                           \
	do {                                   \
		G(r, 0, v[0], v[4], v[8], v[12]);  \
		G(r, 1, v[1], v[5], v[9], v[13]);  \
		G(r, 2, v[2], v[6], v[10], v[14]); \
		G(r, 3, v[3], v[7], v[11], v[15]); \
		G(r, 4, v[0], v[5], v[10], v[15]); \
		G(r, 5, v[1], v[6], v[11], v[12]); \
		G(r, 6, v[2], v[7], v[8], v[13]);  \
		G(r, 7, v[3], v[4], v[9], v[14]);  \
	} while (0)

static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES])
{
	uint64_t m[16];
	uint64_t v[16];
	size_t i;

	for (i = 0; i < 16; ++i) {
		m[i] = load64(block + i * sizeof(m[i]));
	}

	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (i = 0; i < 8; ++i) {
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
	}
}

#undef G
#undef ROUND

int blake2b_update(blake2b_state *S, const void *pin, size_t inlen)
{
	const unsigned char *in = (const unsigned char *)pin;
	if (inlen > 0) {
		size_t left = S->buflen;
		size_t fill = BLAKE2B_BLOCKBYTES - left;
		if (inlen > fill) {
			S->buflen = 0;
			memcpy(S->buf + left, in, fill); /* Fill buffer */
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, S->buf); /* Compress */
			in += fill;
			inlen -= fill;
			while (inlen > BLAKE2B_BLOCKBYTES) {
				blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
				blake2b_compress(S, in);
				in += BLAKE2B_BLOCKBYTES;
				inlen -= BLAKE2B_BLOCKBYTES;
			}
		}
		memcpy(S->buf + S->buflen, in, inlen);
		S->buflen += inlen;
	}
	return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen)
{
	uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
	size_t i;

	if (out == NULL || outlen < S->outlen)
		return -1;

	if (blake2b_is_lastblock(S))
		return -1;

	blake2b_increment_counter(S, S->buflen);
	blake2b_set_lastblock(S);
	memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen); /* Padding */
	blake2b_compress(S, S->buf);

	for (i = 0; i < 8; ++i) /* Output full hash to temp buffer */
		store64(buffer + sizeof(S->h[i]) * i, S->h[i]);

	memcpy(out, buffer, S->outlen);
	secure_zero_memory(buffer, sizeof(buffer));
	return 0;
}

/* inlen, at least, should be uint64_t. Others can be size_t. */
int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)
{
	blake2b_state S[1];

	/* Verify parameters */
	if (NULL == in && inlen > 0)
		return -1;

	if (NULL == out)
		return -1;

	if (NULL == key && keylen > 0)
		return -1;

	if (!outlen || outlen > BLAKE2B_OUTBYTES)
		return -1;

	if (keylen > BLAKE2B_KEYBYTES)
		return -1;

	if (keylen > 0) {
		if (blake2b_init_key(S, outlen, key, keylen) < 0)
			return -1;
	} else {
		if (blake2b_init(S, outlen) < 0)
			return -1;
	}

	blake2b_update(S, (const uint8_t *)in, inlen);
	blake2b_final(S, out, outlen);
	return 0;
}

int blake2(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)
{
	return blake2b(out, outlen, in, inlen, key, keylen);
}

//---------------------------------------------------------------------------------------
//endregion

// NOTE: For this test kernel module, do not set too many keys per set
// otherwise the module might require too much memory and crash
#define KEYS_PER_SET 200

static DECLARE_WAIT_QUEUE_HEAD(precompute_wait);
static atomic_t precompute_go = ATOMIC_INIT(1);

static DEFINE_SPINLOCK(lock_set_logging);

static siphash_key_t left[KEYS_PER_SET];  // each key is a u64 key[2]
static siphash_key_t right[KEYS_PER_SET]; // each key is a u64 key[2]
static siphash_key_t *log_integrity_key_set = left;
static siphash_key_t *log_integrity_precomputed_key_set = right;

static size_t key_len;
static int key_index;

struct task_struct *precompute_tsk;

// Sources:
// Dead Store Elimination (Still) Considered Harmful, USENIX 2017
// https://compsec.sysnet.ucsd.edu/secure_memzero.h
//
void erase_from_memory(void *pointer, size_t size_data)
{
	volatile uint8_t *p = pointer;
	while (size_data--)
		*p++ = 0;
}

//region Forward security scheme
//---------------------------------------------------------------------------------------

static int audit_precompute_keys(void *arg)
{
	pr_info("Entering: %s\n", __func__);

	siphash_key_t latest_key = log_integrity_key_set[KEYS_PER_SET - 1];
	int ret;

	while (!kthread_should_stop()) {

		pr_info("Hello! Precomputing set of keys\n");

		// Initialize function variables
		blake2b_state blake_state;

		// Generate KEYS_PER_SET keys and save them to the set
		int curr_key;
		for (curr_key = 0; curr_key < KEYS_PER_SET; curr_key++) {
			ret = blake2b_init(&blake_state, key_len);
			if (ret != 0) {
				pr_err("audit: error blake2b_init (%d)\n", ret);
				break;
			}

			ret = blake2b_update(&blake_state, (uint8_t *)&latest_key, key_len);
			if (ret != 0) {
				pr_err("audit: error blake2b_update (%d)\n", ret);
				break;
			}

			ret = blake2b_final(&blake_state, (uint8_t *)&latest_key, key_len);
			if (ret != 0) {
				pr_err("audit: error blake2b_final (%d)\n", ret);
				break;
			}

			log_integrity_precomputed_key_set[curr_key] = latest_key;
		}

		// Mark this computation as done
		atomic_set(&precompute_go, 0);

		pr_info("Going back to sleep\n");

		// Wait until there are new keys to precompute
		wait_event_interruptible(precompute_wait, (atomic_read(&precompute_go) == 1) || kthread_should_stop());
	}

	pr_info("Leaving: %s\n", __func__);
	return 0;
}


static u64 sign_event(void)
{
	char *log_msg = "Some arbitrary log message"; // log message
	size_t log_msg_len = strlen(log_msg);
	u64 integrity_proof;

	// Lock the set spin lock (just to make sure that nobody is reading from the set)
	spin_lock(&lock_set_logging);

	// Generate the integrity proof with the current key
	integrity_proof = siphash(log_msg, log_msg_len, &(log_integrity_key_set[key_index]));

	// TODO: append the proof to log_msg
	//

	// Erase key from memory
	erase_from_memory(&(log_integrity_key_set[key_index]), key_len);

	// Check if all keys are used
	if (++key_index == KEYS_PER_SET) {

		// Wait for current precomputation to end
		while (atomic_read(&precompute_go) == 1) {
		}

		// Set new set and new key index
		siphash_key_t *swap = log_integrity_key_set;
		log_integrity_key_set = log_integrity_precomputed_key_set;
		log_integrity_precomputed_key_set = swap;
		key_index = 0;

		pr_info("Swapped, first key of new set: %llu %llu\n", log_integrity_key_set[0].key[0], log_integrity_key_set[0].key[1]);

		// Signal precomputing thread to precompute new keys
		atomic_set(&precompute_go, 1);

		// Wake up precomputing thread
		wake_up(&precompute_wait);
	}

	// Release spinlock
	spin_unlock(&lock_set_logging);

	return integrity_proof;
}

static int verify_signature(u64 integrity_proof, siphash_key_t key)
{
	char *log_msg = "Some arbitrary log message"; // log message
	size_t log_msg_len = strlen(log_msg);

	// Regenerate the integrity proof with the current key
	u64 new_proof = siphash(log_msg, log_msg_len, &(key));

	if (new_proof != integrity_proof)
		return -1;

	return 0;
}








static u64 bench_sign_event(char *log_msg, siphash_key_t key)
{
	//size_t log_msg_len = strlen(log_msg);
	size_t  log_msg_len = len;
	u64 integrity_proof;

	// Generate the integrity proof with the current key
	integrity_proof = siphash(log_msg, log_msg_len, &key);

	return integrity_proof;
}




static int bench_verify_signature(u64 integrity_proof, char *log_msg,  siphash_key_t key)
{
	//char *log_msg = "Some arbitrary log message"; // log message
	//size_t log_msg_len = strlen(log_msg);
	size_t  log_msg_len = len;

	// Regenerate the integrity proof with the current key
	u64 new_proof = siphash(log_msg, log_msg_len, &(key));

	if (new_proof != integrity_proof)
		return -1;

	return 0;
}




//****************median function*************************
static int compare(const void* a, const void* b)
{
    unsigned long long arg1 = *(unsigned long long *)a;
    unsigned long long  arg2 = *(unsigned long long *)b;
 
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}
 
unsigned long long median(size_t n, unsigned long long * x) {
    //unsigned long long temp;
    sort(x, n, sizeof(unsigned long long), &compare, NULL);

    if(n%2==0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        return ((x[n/2] + x[n/2 - 1]) / 2);
    } else {
        // else return the element in the middle
        return  x[n/2];
    }
}

//---------------------------------------------------------------------------------------
//endregion

static int __init cryptomod_init(void)
{
	//pr_info("Entering: %s\n", __func__);

	// Compute first key
	int i=0, j=0, ret;
	siphash_key_t first_key;
	key_len = sizeof(first_key);
	get_random_bytes(&first_key, key_len);

	//pr_info("First key computed\n");

	// Precompute first set synchronously
	blake2b_state blake_state;
	siphash_key_t curr_key = first_key;
	siphash_key_t sign_curr_key = first_key;
	siphash_key_t verify_curr_key = first_key;

	u64 sign_tag;
	char *str; 
	str = kmalloc(10240, GFP_KERNEL);
    memset(str,'a',(8192));

	unsigned long long  start_time, end_time, kenny_med[10];
	unsigned long long  mean, my_sd, sd_sum, sum;

	for(i=0;i<10;i++){
		for(j=0;j<iteration;j++){
			//sign
			ret = blake2b_init(&blake_state, key_len);
			ret = blake2b_update(&blake_state, (uint8_t *)&sign_curr_key, key_len);
			ret = blake2b_final(&blake_state, (uint8_t *)&sign_curr_key, key_len);
			sign_tag = bench_sign_event(str, sign_curr_key);
			//verification
			start_time = ktime_get_ns();
			ret = blake2b_init(&blake_state, key_len);
			ret = blake2b_update(&blake_state, (uint8_t *)&verify_curr_key, key_len);
			ret = blake2b_final(&blake_state, (uint8_t *)&verify_curr_key, key_len);
			if (bench_verify_signature(sign_tag, str, verify_curr_key) == -1) {
					pr_info("Failed verification for %d-th log entry\n", i);
					break;
			}
			end_time = ktime_get_ns();
			my_time[j] = end_time - start_time;

		}
		kenny_med[i] =  median(iteration,  my_time); 
		msleep(100);
	}

	sum =0;
	for(i=0;i<10;i++) sum +=kenny_med[i];
	mean = (sum/10);
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(kenny_med[i]-mean)*(kenny_med[i]-mean);
	my_sd = sd_sum/10;
	my_sd = int_sqrt(my_sd);

	pr_info("\n(KennyLoggings Verify): median time =%llu ns, standard deviation = %llu\n", kenny_med[0], my_sd);
	#if 0
	for (i = 0; i < KEYS_PER_SET; i++) {
		ret = blake2b_init(&blake_state, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_init (%d)\n", ret);
			break;
		}

		ret = blake2b_update(&blake_state, (uint8_t *)&curr_key, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_update (%d)\n", ret);
			break;
		}

		ret = blake2b_final(&blake_state, (uint8_t *)&curr_key, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_final (%d)\n", ret);
			break;
		}

		log_integrity_key_set[i] = curr_key;
	}

	pr_info("First set of keys computed\n");

	// Precompute second set asynchronously
	precompute_tsk = kthread_run(audit_precompute_keys, NULL, "audit_precompute_keys");
	if (IS_ERR(precompute_tsk)) {
		int err = PTR_ERR(precompute_tsk);
		pr_info("Failed to start the precompute_tsk thread (%d)\n", err);
	}

	pr_info("Second set of keys computing\n");
	msleep(100);

	// Sign some log events
	int logs_to_sign = 800; // Do not put too many logs here otherwise it might require too much memory and the module would crash
	u64 integrity_proofs[logs_to_sign];
	for (i = 0; i < logs_to_sign; i++) {
		integrity_proofs[i] = sign_event();
	}

	pr_info("Signatures generated\n");

	// Verify all signatures
	for (i = 0; i < logs_to_sign; i++) {
		ret = blake2b_init(&blake_state, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_init (%d)\n", ret);
			break;
		}

		ret = blake2b_update(&blake_state, (uint8_t *)&first_key, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_update (%d)\n", ret);
			break;
		}

		ret = blake2b_final(&blake_state, (uint8_t *)&first_key, key_len);
		if (ret != 0) {
			pr_err("audit: error blake2b_final (%d)\n", ret);
			break;
		}

		if (verify_signature(integrity_proofs[i], first_key) == -1) {
			pr_info("Failed verification for %d-th log entry\n", i);
			break;
		}
	}

	pr_info("Verification phase completed\n");

	kthread_stop(precompute_tsk);
#endif 

	

	//pr_info("Leaving: %s\n", __func__);
	return 0;
}

static void __exit cryptomod_exit(void)
{
	pr_info("Module removed.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_exit);

MODULE_LICENSE("GPL");
