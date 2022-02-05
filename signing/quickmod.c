#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <asm/i387.h>
#define  _MM_MALLOC_H_INCLUDED
#include <x86intrin.h>
#undef _MM_MALLOC_H_INCLUDED


#define len  1024 //generating size
#define iteration 100000
static DEFINE_SPINLOCK(lock_set_logging);
typedef __m128i block;
typedef struct {block rd_key[11]; } AES_KEY;

const static unsigned char aeskey[16] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p'};
static AES_KEY const_aeskey;
static block current_key, current_state;

/* Some helper functions */
#define rnds 10 //AES rounds
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define zero_block()          _mm_setzero_si128()
/*Load 14-byte log data after the 2-byte counter*/
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)

/********************************************************************/
// AES Key Expansion
// Sources: OCB Version 3 Reference Code (Optimized C)  
// https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
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

//-----------some helper functions------------------------------

//Generate 7-block MAC1 inputs
#define gen_7_blks(cipher_blks,log_msg,counter)                            \
    do{                                                                    \
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),counter+2); \
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),counter+3); \
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),counter+4); \
		cipher_blks[4]  = gen_logging_blk((block*)(log_msg+54),counter+5); \
		cipher_blks[5]  = gen_logging_blk((block*)(log_msg+68),counter+6); \
		cipher_blks[6]  = gen_logging_blk((block*)(log_msg+82),counter+7); \
		cipher_blks[7]  = gen_logging_blk((block*)(log_msg+96),counter+8); \
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



#define aes_enclasr_8(cipher_blks,sched)                              \
	do{                                                              \
		cipher_blks[0] = _mm_aesenclast_si128(cipher_blks[0], sched[rnds]); \
		cipher_blks[1] =  _mm_aesenclast_si128(cipher_blks[1], sched[rnds]); \
		cipher_blks[2] =  _mm_aesenclast_si128(cipher_blks[2], sched[rnds]); \
		cipher_blks[3] =  _mm_aesenclast_si128(cipher_blks[3], sched[rnds]); \
		cipher_blks[4] =  _mm_aesenclast_si128(cipher_blks[4], sched[rnds]); \
		cipher_blks[5] = _mm_aesenclast_si128(cipher_blks[5], sched[rnds]); \
		cipher_blks[6] = _mm_aesenclast_si128(cipher_blks[6], sched[rnds]); \
		cipher_blks[7] =  _mm_aesenclast_si128(cipher_blks[7], sched[rnds]); \
	} while(0)



#define ecb_8(cipher_blks,sched)           \
	do{                                    \
		aes_enc_8(cipher_blks,sched, 1);   \
		aes_enc_8(cipher_blks,sched, 2);   \
		aes_enc_8(cipher_blks,sched, 3);   \
		aes_enc_8(cipher_blks,sched, 4);   \
		aes_enc_8(cipher_blks,sched, 5);   \
		aes_enc_8(cipher_blks,sched, 6);   \
		aes_enc_8(cipher_blks,sched, 7);   \
		aes_enc_8(cipher_blks,sched, 8);   \
		aes_enc_8(cipher_blks,sched, 9);   \
		aes_enclasr_8(cipher_blks,sched);  \
	} while(0)


//XOR 8 cipher blocks
#define tag_8_xor(tag_blks,cipher_blks)                                                                       \
  do{                                                                                                              \
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

#define enc_2(cipher_blks, key)                                 \
	do{                                                         \
		cipher_blks[0] = _mm_aesenc_si128(cipher_blks[0], key); \
		cipher_blks[1] = _mm_aesenc_si128(cipher_blks[1], key); \
  	}while(0)


/*Marcos used to unrolling ECB*/

//aes_single's pre-round outside the macros
#define aes_single(cipher_blk, sched)                        \
	do{                                                      \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[1]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[2]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[3]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[4]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[5]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[6]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[7]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[8]); \
		cipher_blk = _mm_aesenc_si128(cipher_blk, sched[9]); \
		cipher_blk =_mm_aesenclast_si128(cipher_blk, sched[10]);\
	} while(0)


#define AES_ECB_2(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		cipher_blks[0] =_mm_xor_si128(cipher_blks[0], sign_keys); \
		cipher_blks[1] =_mm_xor_si128(cipher_blks[1], sign_keys); \
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





static void first_blks(block *cipher_blks, uint16_t counter, unsigned char *log_msg, block *sched, block sign_keys)
{
		//int j =1;
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);	
		AES_ECB_8(cipher_blks, sched, sign_keys);			
}

 static void cmpt_8_blks(block *cipher_blks, uint16_t counter, unsigned char *log_msg, block *sched, block sign_keys)
 {
	cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
	gen_7_blks(cipher_blks,log_msg,counter);
	AES_ECB_8(cipher_blks,sched, sign_keys);	
	//ecb_8(cipher_blks,sched);
}

static void cmpt_4_blks(block *cipher_blks, uint16_t counter, const unsigned char *log_msg, const block *sched, block sign_keys)
{
		if(counter){		
			cipher_blks[0]  = gen_logging_blk((block*)(log_msg),counter+1); 
		}else{//contains the first block
			cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
			cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		}
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),counter+2); 
		cipher_blks[2]  = gen_logging_blk((block*)(log_msg+26),counter+3); 
		cipher_blks[3]  = gen_logging_blk((block*)(log_msg+40),counter+4); 
		AES_ECB_4(cipher_blks,sched, sign_keys);	
}


static void cmpt_2_blks(block *cipher_blks, uint16_t counter, const unsigned char *log_msg, block *sched, block sign_keys)
{
		if(counter){		
			cipher_blks[0]  = gen_logging_blk((block*)(log_msg),counter+1); //Not the first block
		}else{//contains the first block
			cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
			cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		}
		cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),counter+2); 
		AES_ECB_2(cipher_blks,sched, sign_keys);	
}

/** Initial:
*** Expand AES round keys
*** Genreate first signing key and state pair 
**/
static void crypto_int(void)
{
	unsigned char s_0[16];/* initial State */
	block mask, init_pair[2];
	block * sched;
	get_random_bytes(s_0, 16);
	/* initial State */
	kernel_fpu_begin();	
	AES_128_Key_Expansion(aeskey,&const_aeskey); //inital aes round keys
	/*generating the first key-stae pair*/
	sched = ((block *)(const_aeskey.rd_key));
	mask = xor_block(sched[0], *(block *)s_0);/*xor the intial state with the aes fixed key*/
	AES_ECB_2(init_pair, sched, mask);
	current_state = xor_block(init_pair[0], *(block *)s_0);
	current_key = xor_block(init_pair[1], *(block *)s_0);
	kernel_fpu_end();
}

/**  
* MAC, signing a log message and updating the signing-key & state
* Input @log_msg: a log data, 
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: a 64-byte tag
**/
static inline __u64 mac_core(unsigned char *log_msg, size_t msg_len)
{
	uint16_t j, remaining, counter;
	//tmp: used for padding the last block
	union { uint16_t u16[8]; uint8_t u8[16]; block bl; } tmp;
	block * sched, *out;
	block mask, cipher_blks[9], tag_blks[3];
	block next[2];
	__u64 proof[2];
	int nblks;
	nblks = (msg_len/112); 
	remaining=(uint16_t)(msg_len%112);
	counter =0;
	sched = ((block *)(const_aeskey.rd_key)); //point to AES round keys	
	out = ((block *)(proof));
	//xor the signing key with the aes fixed key
	mask =_mm_xor_si128(sched[0], current_key);
	tag_blks[2] = current_key;

	if(nblks)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_8_xor(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;	
		--nblks;
		while(nblks){	
			//cmpt_8_blks(cipher_blks, counter, log_msg, sched, mask);
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_8_xor(tag_blks,cipher_blks);
			counter +=8;
			log_msg +=110;
			--nblks;
		}
	}//end of nblks
	if (remaining){
		if(remaining >=56){//4-block, 4*14=56 bytes log data
			cmpt_4_blks(cipher_blks,counter, log_msg, sched, mask);
			tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
			tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
			remaining -= 56;
			counter +=4;
			log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining >= 28) {//2-block, 2*14=28 bytes log data
			//cmpt_2_blks(cipher_blks,counter, log_msg, sched, mask);
			if(counter){ 
				cipher_blks[0]  = gen_logging_blk((block*)(log_msg),counter+1); //Not the first block
			}else{//contains the first block
				cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);
				cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
			}
			cipher_blks[1]  = gen_logging_blk((block*)(log_msg+12),counter+2); 
			AES_ECB_2(cipher_blks,sched, mask);
			tag_blks[2] = xor_block(xor_block(cipher_blks[0], cipher_blks[1]), tag_blks[2]); 
			remaining -= 28;
			counter +=2;
			log_msg +=26;/*28-byte computed, apply 26-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining >= 14) {//1-block 14 bytes log data
			if(counter){
				tmp.bl = _mm_loadu_si128((block*)log_msg);//Not the first block
			}else{//it is the first block
				tmp.bl = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2);//the first block
			}
			tmp.bl = _mm_insert_epi16(tmp.bl, counter+1, 0);
			tmp.bl =_mm_xor_si128(tmp.bl, mask);
			//AES_single(&tmp.bl, sched);
			aes_single(tmp.bl, sched);
			tag_blks[2] = xor_block(tag_blks[2], tmp.bl);
			remaining -= 14;
			counter +=1;
			log_msg +=12;/*14-byte computed, apply 12-byte, leaving 2-byte overwrote by counter*/
		}
		if (remaining){//last block + generating new key
			if (counter)  log_msg +=2;
			counter +=(14-remaining);
			tmp.bl = zero_block();
			tmp.u16[0]= counter;
			memcpy(&tmp.u8[2], log_msg, remaining);
			//AES_single(&tmp.bl, sched);
			tmp.bl = xor_block(tmp.bl, mask);
			aes_single(tmp.bl, sched);
			/*AES Preround */	
		}
		*out = tag_blks[2];
    }
	next[0] = current_state;//0 xor ase_key xor current_state
	next[1] = xor_block(sched[0], next[1]); //1 xor ase_key xor current_state
	mask =_mm_xor_si128(sched[0], current_state);
	AES_ECB_2(next, sched, mask);
	current_key = xor_block(next[0], current_state);
	current_state = xor_block(next[1], current_state);
	//kernel_fpu_end();
	return proof[0];
}

#undef gen_7_blks
#undef prernd_8
#undef prernd_4
#undef AES_ECB_8



static int __init cryptomod_init(void)
{
	pr_info("Module started.\n");
	unsigned char str[8200]; 
    memset(str,'a',(8192));
    int j, times;
	times = iteration+8000;
	__u64 tag;	
	crypto_int();
	pr_info("------crypto_int is done ----------\n");

	for(j=0;j<times;j++)
	{	
		kernel_fpu_begin();
		tag = mac_core(str,len);
		kernel_fpu_end();
		
		if (j==8000) pr_info("----Mac Starts---- \n");
		
	}
	pr_info("-----Mac End-----\n");
	return 0;
}

static void __exit cryptomod_exit(void)
{
	pr_info("Module removed.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_exit);

MODULE_LICENSE("GPL");