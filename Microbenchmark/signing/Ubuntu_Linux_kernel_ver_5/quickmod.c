#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/sort.h>
#include <linux/moduleparam.h>

//#include <asm/i387.h>//linux version <5
#include <asm/fpu/api.h> //version =5



#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED

#include <linux/siphash.h>

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>


static int len= 256; //generating size
module_param(len,int,S_IRUGO);  

#define iteration 200000


typedef __m128i block;
typedef struct {block rd_key[11]; } AES_KEY;

const static unsigned char aeskey[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
static AES_KEY const_aeskey;
static block current_key, current_state, q2_tag;
static unsigned long long my_time[1048576];

/* Some helper functions */
#define rnds 10 //AES rounds
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define zero_block()          _mm_setzero_si128()
/*Load 14-byte log data after the 2-byte counter*/
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)

// Sources:
// Dead Store Elimination (Still) Considered Harmful, USENIX 2017
// https://compsec.sysnet.ucsd.edu/secure_memzero.h
//
#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
  do{                                                                       \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2);                                              \
  } while(0)


void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}
#undef EXPAND_ASSIST

//----------------------------------------------------

//AES pre-round 8 blocks

#define gen_7_blks(cipher_blks,log_msg,counter)                            \
    do{                                                                    \
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); \
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),(counter+3)); \
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),(counter+4)); \
		cipher_blks[4]  = gen_logging_blk((block*)(log_msg+54),(counter+5)); \
		cipher_blks[5]  = gen_logging_blk((block*)(log_msg+68),(counter+6)); \
		cipher_blks[6]  = gen_logging_blk((block*)(log_msg+82),(counter+7)); \
		cipher_blks[7]  = gen_logging_blk((block*)(log_msg+96),(counter+8)); \
	} while(0)


//AES pre-round 8 blocks
#define prernd_8(cipher_blks, key)                       \
	do{                                                  \
		cipher_blks[0] = xor_block(cipher_blks[0], key); \
		cipher_blks[1] = xor_block(cipher_blks[1], key); \
		cipher_blks[2] = xor_block(cipher_blks[2], key); \
		cipher_blks[3] = xor_block(cipher_blks[3], key); \
		cipher_blks[4] = xor_block(cipher_blks[4], key); \
		cipher_blks[5] = xor_block(cipher_blks[5], key); \
		cipher_blks[6] = xor_block(cipher_blks[6], key); \
		cipher_blks[7] = xor_block(cipher_blks[7], key); \
	} while(0)
	
//AES Pre-round 4 blocks
#define prernd_4(cipher_blks,sign_keys) 			       \
  do{                                                      \
    cipher_blks[0] = xor_block(cipher_blks[0], sign_keys); \
    cipher_blks[1] = xor_block(cipher_blks[1], sign_keys); \
    cipher_blks[2] = xor_block(cipher_blks[2], sign_keys); \
    cipher_blks[3] = xor_block(cipher_blks[3], sign_keys); \
  } while(0)


//XOR 8 cipher blocks

#define tag_8_xor(tag_blks,cipher_blks)  \
  do{  \
	tag_blks[0] =xor_block(xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  \
	tag_blks[1] =xor_block(xor_block(cipher_blks[4], cipher_blks[5]), xor_block(cipher_blks[6], cipher_blks[7]));  \
	tag_blks[2] =xor_block(tag_blks[2], xor_block(tag_blks[0], tag_blks[1]));                                      \
  } while(0)


#define enc_8(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
		cipher_blks[4] = _mm_aesenc_si128(cipher_blks[4], key); \
		cipher_blks[5] = _mm_aesenc_si128(cipher_blks[5], key); \
		cipher_blks[6] = _mm_aesenc_si128(cipher_blks[6], key); \
		cipher_blks[7] = _mm_aesenc_si128(cipher_blks[7], key); \
  	}while(0)



#define enc_4(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
		cipher_blks[3] = _mm_aesenc_si128(cipher_blks[3], key); \
  	}while(0)


#define enc_3(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
		cipher_blks[2] = _mm_aesenc_si128(cipher_blks[2], key); \
  	}while(0)


#define enc_2(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
  	}while(0)


/*Marcos used to unrolling ECB*/

#define aes_single(cipher_blks, sched)                               \
	do{                                                              \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[1]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[2]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[3]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[4]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[5]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[6]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[7]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[8]); \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], sched[9]); \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]);\
	} while(0)


#define AES_ECB_2(cipher_blks, sched)   \
	do{     \
		enc_2(cipher_blks, sched[1]);              \
		enc_2(cipher_blks, sched[2]);              \
		enc_2(cipher_blks, sched[3]);              \
		enc_2(cipher_blks, sched[4]);              \
		enc_2(cipher_blks, sched[5]);              \
		enc_2(cipher_blks, sched[6]);              \
		enc_2(cipher_blks, sched[7]);              \
		enc_2(cipher_blks, sched[8]);              \
		enc_2(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)


#define AES_ECB_3(cipher_blks, sched)    \
	do{                                  \
		enc_3(cipher_blks, sched[1]);              \
		enc_3(cipher_blks, sched[2]);              \
		enc_3(cipher_blks, sched[3]);              \
		enc_3(cipher_blks, sched[4]);              \
		enc_3(cipher_blks, sched[5]);              \
		enc_3(cipher_blks, sched[6]);              \
		enc_3(cipher_blks, sched[7]);              \
		enc_3(cipher_blks, sched[8]);              \
		enc_3(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
	}while (0)



#define AES_ECB_4(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_4(cipher_blks,sign_keys);           \
		enc_4(cipher_blks, sched[1]);              \
		enc_4(cipher_blks, sched[2]);              \
		enc_4(cipher_blks, sched[3]);              \
		enc_4(cipher_blks, sched[4]);              \
		enc_4(cipher_blks, sched[5]);              \
		enc_4(cipher_blks, sched[6]);              \
		enc_4(cipher_blks, sched[7]);              \
		enc_4(cipher_blks, sched[8]);              \
		enc_4(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
	}while (0)



#define AES_ECB_8(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		prernd_8(cipher_blks,sign_keys);           \
		enc_8(cipher_blks, sched[1]);              \
		enc_8(cipher_blks, sched[2]);              \
		enc_8(cipher_blks, sched[3]);              \
		enc_8(cipher_blks, sched[4]);              \
		enc_8(cipher_blks, sched[5]);              \
		enc_8(cipher_blks, sched[6]);              \
		enc_8(cipher_blks, sched[7]);              \
		enc_8(cipher_blks, sched[8]);              \
		enc_8(cipher_blks, sched[9]);              \
		cipher_blks[0] =_mm_aesenclast_si128(cipher_blks[0], sched[10]); \
		cipher_blks[1] =_mm_aesenclast_si128(cipher_blks[1], sched[10]); \
		cipher_blks[2] =_mm_aesenclast_si128(cipher_blks[2], sched[10]); \
		cipher_blks[3] =_mm_aesenclast_si128(cipher_blks[3], sched[10]); \
		cipher_blks[4] =_mm_aesenclast_si128(cipher_blks[4], sched[10]); \
		cipher_blks[5] =_mm_aesenclast_si128(cipher_blks[5], sched[10]); \
		cipher_blks[6] =_mm_aesenclast_si128(cipher_blks[6], sched[10]); \
		cipher_blks[7] =_mm_aesenclast_si128(cipher_blks[7], sched[10]); \
	}while (0)


//end of marcos---------------------------------------------

static void cmpt_4_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{
	if(counter){		
		cipher_blks[0]  = gen_logging_blk((block*)(log_msg),counter+1); 
	}else{//contains the first block
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
	}
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); 
	cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),(counter+3)); 
	cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),(counter+4)); 
	AES_ECB_4(cipher_blks, sched, sign_keys);
}


static void cmpt_2_blks(block *cipher_blks, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{
	if(counter){		
		cipher_blks[0]  = gen_logging_blk((block*)(log_msg),(counter+1)); //Not the first block
	}else{//contains the first block
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], (counter+1), 0);
	}
	cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),(counter+2)); 
	cipher_blks[0] =_mm_xor_si128(cipher_blks[0], sign_keys); 
	cipher_blks[1] =_mm_xor_si128(cipher_blks[1], sign_keys); 
	AES_ECB_2(cipher_blks,sched);
}


static void cmpt_a_blk(block* cipher_blk, uint16_t counter, const char *log_msg, const block *sched, block sign_keys)
{	
	if(counter){
			*cipher_blk = _mm_loadu_si128((block*)log_msg);//Not the first block
	}else{//it is the first block
			*cipher_blk = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);//the first block
	}
	*cipher_blk = _mm_insert_epi16(*cipher_blk, counter+1, 0);
	/*AES Preround */
	*cipher_blk =_mm_xor_si128(*cipher_blk, sign_keys);
	aes_single(cipher_blk, sched);
}

/*Initial*/

static void crypto_int(void)
{
	block s_0, mask;
	block init_pair[2];
	block * sched;
	get_random_bytes(&s_0, sizeof(block));/*initial State */
	
	kernel_fpu_begin();	
	
	AES_128_Key_Expansion(aeskey,&const_aeskey); //inital aes round keys
	init_pair[0] = zero_block();/*0 for updatting state*/
	init_pair[1] = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);/*1 for updatting key*/
	sched = ((block *)(const_aeskey.rd_key)); 
	mask =xor_block(s_0, sched[0]);
	init_pair[0] = xor_block(init_pair[0], mask);
	init_pair[1] = xor_block(init_pair[1], mask);
	AES_ECB_2(init_pair, sched);
	current_state = xor_block(init_pair[0], s_0);
	current_key = xor_block(init_pair[1], s_0);

	kernel_fpu_end();
}


/**  
* MAC, signing a log message and updating the signing-key & state
* Input @log_msg: a log data,  
        @msg_len: the length of the log data 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: T(64-byte tag)
**/ 
static __u64 mac_core( const char *log_msg, const int msg_len)
{
	block mask, cipher_blks[8], tag_blks[3];
	unsigned char my_pad[16];
	__u64 out_tmp[2];
	register block * sched = ((block *)(const_aeskey.rd_key)); 
	register block * aes_blks = cipher_blks;
	block *pad_zeros;
	uint16_t remaining, counter, *pad_header;
	
	remaining = (uint16_t)msg_len;
	counter =0;
	pad_header = ((uint16_t*)(my_pad));	
	pad_zeros = ((block *)(my_pad));

	
	mask = _mm_xor_si128(sched[0], current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(&current_key);

	if(remaining>=112)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_8_xor(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;/*112-byte computed, apply 110-byte, leaving 2-byte overwrote by counter*/	
		remaining -= 112;
		while(remaining >= 112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_8_xor(tag_blks,cipher_blks);/*)Xor each block*/
			counter += 8;
			log_msg += 110;
			remaining -= 112;
		}
	}//end of nblks
	
	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(aes_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
		cmpt_2_blks(aes_blks, counter, log_msg, sched, mask);
		//AES_ECB_2(aes_blks,sched);
		tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
		remaining -= 28;
		counter +=2;
		log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 14) {//1-block 14 bytes log data
		cmpt_a_blk(&aes_blks[0],counter, log_msg, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], cipher_blks[0]);
		remaining -= 14;
		counter +=1;
		log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
	}
#if 1
	if (remaining){//last block + generating new key
		if (counter)  log_msg +=2;
		counter += (14-remaining);
		* pad_zeros = zero_block();
		* pad_header = counter;
		memcpy(&my_pad[2], log_msg, remaining);
		cipher_blks[0] = xor_block( mask, *(block*)my_pad);
		cipher_blks[1] = xor_block(current_state, sched[0]);
		cipher_blks[2] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));
		AES_ECB_3(cipher_blks, sched);
		tag_blks[2] = xor_block(cipher_blks[0], tag_blks[2]);
		current_key = xor_block(cipher_blks[2], current_state);
		current_state = xor_block(cipher_blks[1], current_state);
	}else{
		//pr_info("no remaining!\n");
		cipher_blks[0] = xor_block(current_state, sched[0]);/*0 for updatting state*/
		cipher_blks[1] = xor_block(cipher_blks[0], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));/*1 for updatting key*/
		AES_ECB_2(cipher_blks, sched);
		current_key = xor_block(cipher_blks[1], current_state);
		current_state = xor_block(cipher_blks[0], current_state);
	}
#endif
	_mm_store_si128((block*)out_tmp, tag_blks[2]);

	return (out_tmp[0]);
}












/**  
* QuickLog2: updating the tag, signing-key & state
* Input @log_msg: a log data, @msg_len: the length of the data
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* 
**/
static void mac_core_2(const char *log_msg, const int msg_len)
{
	block mask, cipher_blks[8], tag_blks[3];
	unsigned char my_pad[16];

	register block * sched = ((block *)(const_aeskey.rd_key)); 
	register block * aes_blks = cipher_blks;
	block *pad_zeros;
	uint16_t remaining, counter, *pad_header;
	
	remaining = (uint16_t)msg_len;
	counter =0;
	pad_header = ((uint16_t*)(my_pad));	
	pad_zeros = ((block *)(my_pad));

	
	mask = _mm_xor_si128(sched[0], current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(&current_key);

	if(remaining>=112)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_8_xor(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;/*112-byte computed, apply 110-byte, leaving 2-byte overwrote by counter*/	
		remaining -= 112;
		while(remaining >= 112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_8_xor(tag_blks,cipher_blks);/*)Xor each block*/
			counter += 8;
			log_msg += 110;
			remaining -= 112;
		}
	}//end of nblks
	
	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(aes_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
		cmpt_2_blks(aes_blks, counter, log_msg, sched, mask);
		//AES_ECB_2(aes_blks,sched);
		tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
		remaining -= 28;
		counter +=2;
		log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 14) {//1-block 14 bytes log data
		cmpt_a_blk(&aes_blks[0],counter, log_msg, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], cipher_blks[0]);
		remaining -= 14;
		counter +=1;
		log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
	}

	if (remaining){//last block + generating new key
		if (counter)  log_msg +=2;
		counter += (14-remaining);
		* pad_zeros = zero_block();
		* pad_header = counter;
		memcpy(&my_pad[2], log_msg, remaining);
		cipher_blks[0] = xor_block( mask, *(block*)my_pad);
		cipher_blks[1] = xor_block(current_state, sched[0]);
		cipher_blks[2] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));
		AES_ECB_3(cipher_blks, sched);
		tag_blks[2] = xor_block(cipher_blks[0], tag_blks[2]);
		current_key = xor_block(cipher_blks[2], current_state);
		current_state = xor_block(cipher_blks[1], current_state);
		q2_tag = xor_block(tag_blks[2], q2_tag );	
	}else{
		//pr_info("no remaining!\n");
		cipher_blks[0] = xor_block(current_state, sched[0]);/*0 for updatting state*/
		cipher_blks[0] = xor_block(cipher_blks[1], _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000));/*1 for updatting key*/
		AES_ECB_2(cipher_blks, sched);
		current_key = xor_block(cipher_blks[1], current_state);
		current_state = xor_block(cipher_blks[0], current_state);
		q2_tag = xor_block(tag_blks[2], q2_tag );	
	}


}

#undef gen_7_blks
#undef prernd_8
#undef prernd_4
#undef tag_8_xor
#undef enc_8
#undef enc_4
#undef enc_3
#undef enc_2
#undef aes_single
#undef AES_ECB_2
#undef AES_ECB_3
#undef AES_ECB_4
#undef AES_ECB_8


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
//**************************KennyLogging Part***************************************
// Sources:
// Riccardo Paccagnella,Kevin Liao, Dave Tian, and Adam Bates. 
// Logging to the danger zone: Race condition attacks and defenses on system audit frameworks. In CCS 2020, pages 1551–1574, 2020.
// https://bitbucket.org/sts-lab/kennyloggings/src/master/kernel-module/
void erase_from_memory(void *pointer, size_t size_data)
{
	volatile uint8_t *p = pointer;
	while (size_data--)
		*p++ = 0;
}


static u64 sign_event(char *log_msg, siphash_key_t first_key,size_t key_len)
{
	//size_t log_msg_len = strlen(log_msg);
	size_t  log_msg_len = len;
	u64 integrity_proof;

	// Generate the integrity proof with the current key
	integrity_proof = siphash(log_msg, log_msg_len, &first_key);

	return integrity_proof;
}



//---------------------------------------------------------------------------------------
//endregion


static int __init benchmarking(void)
{
	
	int i, j;
	char *str; 
	unsigned long long  start_time, end_time, appd_med, kenny_med[10], quick_med[10], quick_2_med[10];
	unsigned long long  mean, q_sd, q2_sd, k_sd, sd_sum, sum;
	__u64  quick_tag, kenny_tag;
	size_t key_len;
	siphash_key_t first_key;
	struct audit_buffer *ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_SYSCALL);
    //audit_log_format(ab, "arch=c000003e syscall=9 success=yes exit=139641477644288 a0=7f00d0abc000 a1=2000 a2=3 a3=812 items=0 ppid=1234 pid=5776 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm=\"sudo\" exe=\"/usr/bin/sudo\" key=(null)");


	key_len = sizeof(first_key);
	str = kmalloc(10240, GFP_KERNEL);
    memset(str,'a',(8192));


	pr_info("\n_______Starting: log size = %dB______\n", len);
	crypto_int();
	
	msleep(100);


/*************************************QuickLog*************************************************/	
	
	//Quicklog signing a message
	for(i=0;i<10;i++){
		for(j=0;j<iteration;j++)
		{	
			
			start_time = ktime_get_ns();

			kernel_fpu_begin();
			quick_tag = mac_core(str, len);
			kernel_fpu_end();
			
			end_time = ktime_get_ns();
			
			my_time[j] = end_time - start_time;
			
		}
		
		quick_med[i] =  median(iteration,  my_time);  


		msleep(100);
	}
	sum =0;
	for(i=0;i<10;i++) sum +=quick_med[i];
	mean = (sum/10);
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(quick_med[i]-mean)*(quick_med[i]-mean);
	q_sd = sd_sum/10;
	q_sd = int_sqrt(q_sd);

	msleep(100);

	

/*************************************QuickLog2*************************************************/
	for(i=0;i<10;i++){
		for(j=0;j<iteration;j++)
		{	

			start_time = ktime_get_ns();

			kernel_fpu_begin();
			mac_core_2(str, len);
			kernel_fpu_end();
			
			end_time = ktime_get_ns();
			
			my_time[j] = end_time - start_time;
			
		}
		
		quick_2_med[i] =  median(iteration,  my_time);  

		msleep(100);
	}


	sum =0;
	for(i=0;i<10;i++) sum +=quick_2_med[i];
	mean = (sum/10);
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(quick_2_med[i]-mean)*(quick_2_med[i]-mean);
	q2_sd = sd_sum/10;
	q2_sd = int_sqrt(q2_sd);

	

	msleep(100);
/*************************************Kennylogging *********************************/
	
	//Kennylogging signing a message
	for(i=0;i<10;i++){
	for(j=0;j<iteration;j++)
		{
			get_random_bytes(&first_key, key_len);

			start_time = ktime_get_ns();
			kenny_tag = sign_event(str, first_key, key_len);
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
	k_sd = sd_sum/10;
	k_sd = int_sqrt(k_sd);


   //Erasing Kennylogging's current key

	for(j=0;j<iteration;j++)
	{
		get_random_bytes(&first_key, key_len);

		start_time = ktime_get_ns();
		erase_from_memory(&first_key, key_len);
		end_time = ktime_get_ns();
		my_time[j] = end_time - start_time;
		
	}
	kenny_med[0] +=  median(iteration,  my_time);  

	msleep(100);


	// Appending the tag to the log message	
	audit_log_format(ab, "type=SOCKADDR msg=audit(1650461786.949:105297428)  : saddr=0100");
	
	for(j=0;j<1000;j++)
	{	

		start_time = ktime_get_ns();

		audit_log_format(ab, " p=%llx", kenny_tag);
		
		end_time = ktime_get_ns();
		
		my_time[j] = end_time - start_time;
		
	}
	appd_med = median(1000,  my_time);
	kenny_med[0] +=  appd_med;  
	quick_med[0] +=  appd_med;


	pr_info("-[QuickLog Sign]-: median time =%llu ns, standard deviation = %llu\n", quick_med[0], q_sd);
	pr_info("--[QuickLog2 Sign]--: median time =%llu ns, standard deviation = %llu\n", quick_2_med[0], q2_sd);
	pr_info("(KennyLoggings Sign): median time =%llu ns, standard deviation = %llu\n", kenny_med[0], k_sd);

	pr_info("\n-----------------------------------------------------------\n");
	msleep(20000);
	return 0;
}
static void __exit quickmod_exit(void)
{
	pr_info("Module removed:%s \n", __func__);
}

module_init(benchmarking);
module_exit(quickmod_exit);

MODULE_LICENSE("GPL");