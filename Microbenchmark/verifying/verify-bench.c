#include <time.h>
#include <stdio.h>
#include <string.h>   
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>

#include <x86intrin.h>
#include <immintrin.h>
#include <emmintrin.h>   
#include <wmmintrin.h>
/* Define standard sized integers  */
#if defined(_MSC_VER) && (_MSC_VER < 1600)
	typedef unsigned __int8  uint8_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef          __int64 int64_t;
#else
	#include <stdint.h>
#endif

/* Some helper functions */
#define ITERATIONS 200000
#define rnds 10 //AES rounds
typedef __m128i block;
typedef struct { __m128i rd_key[11]; } AES_KEY;

const static unsigned char aeskey[16] = {0};
static AES_KEY const_aeskey;
static block signing_pair[16];
static block s_0;/* initial State */
static int  len;
static unsigned long long my_time[320000], quick_med[10];

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
#define xor_block(x,y)   _mm_xor_si128(x,y)
#define zero_block()    _mm_setzero_si128()

//Load 14-byte log data after the 2-byte counter
#define gen_logging_blk(log,ctr) _mm_insert_epi16(_mm_loadu_si128(log), ctr, 0)

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


//XOR 8 cipher blocks
#define tag_blks_xor_8(tag_blks,cipher_blks)                                                                       \
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


#define aes_single(cipher_blks, sched, sign_keys)  \
	do{      \
		cipher_blks[0] = _mm_xor_si128(cipher_blks[0], sign_keys); \
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



#define AES_ECB_2(cipher_blks, sched, sign_keys)   \
	do{                                        	   \
		cipher_blks[0] =_mm_xor_si128(cipher_blks[0], sign_keys); \
		cipher_blks[1] =_mm_xor_si128(cipher_blks[1], sign_keys); \
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



static void cmpt_4_blks(block *cipher_blks, uint16_t counter, const char *log_msg, block *sched, block sign_keys)
{

	if(counter){//Not the first block		
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


//*********************** end of help functions *************************************

/*Updating a key-sate pair using the current_state */
void my_update(block * next_pair,  const block * current_state, const block *sched_key)
{
	block update_pair[2];
	block mask = xor_block(sched_key[0], *current_state);
	update_pair[0] = zero_block();/*0 for updatting state*/
	update_pair[1] = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);/*1 for updatting key*/
	
	AES_ECB_2(update_pair,sched_key, mask);
	next_pair[0] = xor_block(update_pair[0], *current_state);
	next_pair[1] = xor_block(update_pair[1], *current_state);
}



uint64_t sign_core( const unsigned char *log_msg, const int *len,  const block *current_key)
{
	uint16_t remaining, counter;
	size_t msg_len = *len;
	//tmp: used for padding the last block
	union { uint16_t u16[8]; uint8_t u8[16]; block bl; } tmp;
	register block * sched =((block *)(const_aeskey.rd_key)); //point to AES round keys	;
	block mask, cipher_blks[8], tag_blks[3];
	union { uint64_t u64[2]; block bl; } out;

	//int nblks;
	//nblks = (msg_len/112); 
	remaining=(uint16_t)(*len);
	counter =0;
	
 
	mask =_mm_xor_si128(sched[0], *current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(current_key);

	if(remaining>=112)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_blks_xor_8(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;	
		remaining -=112;
		while(remaining>=112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_blks_xor_8(tag_blks,cipher_blks);
			counter +=8;
			log_msg +=110;
			remaining -=112;
		}
	}//end of nblks

	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(cipher_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
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
		aes_single(cipher_blks, sched,mask);
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
		while(remaining--){
			tmp.u8[remaining+1]=log_msg[remaining-1];
		}
		tmp.bl = xor_block(tmp.bl, mask);
		aes_single(cipher_blks, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], tmp.bl);	
	}
    
	out.bl = _mm_loadu_si128((block*)&tag_blks[2]);
	return out.u64[0];
}




/**  
* Input @log_msg: a log data, 
        @len: the lenght of input data,
		@current_key: the signing key
* Computing block format: a block(16 bytes) contains "<i>||M_i",  
*                         2 bytes counter(<i>) and 14 bytes log data(M_i)
* Output: a proof, out(uint64_t)
**/
uint64_t verify_core( const unsigned char *log_msg, const int *len,  const block *current_key)
{
	uint16_t remaining, counter;
	size_t msg_len = *len;
	//tmp: used for padding the last block
	union { uint16_t u16[8]; uint8_t u8[16]; block bl; } tmp;
	register block * sched =((block *)(const_aeskey.rd_key)); //point to AES round keys	;
	block mask, cipher_blks[8], tag_blks[3];
	union { uint64_t u64[2]; block bl; } out;

	//int nblks;
	//nblks = (msg_len/112); 
	remaining=(uint16_t)(*len);
	counter =0;
	
 
	mask =_mm_xor_si128(sched[0], *current_key);//xor the signing key with the aes public key
	tag_blks[2] = _mm_loadu_si128(current_key);

	if(remaining>=112)//start 8 blocks parallel computing 
	{
		cipher_blks[0]  = _mm_srli_si128(_mm_loadu_si128((block*)log_msg), 2); 
		cipher_blks[0]  = _mm_insert_epi16(cipher_blks[0], counter+1, 0);
		gen_7_blks(cipher_blks,log_msg,counter);
		AES_ECB_8(cipher_blks,sched, mask);
		tag_blks_xor_8(tag_blks,cipher_blks);
		counter +=8;
		log_msg +=110;	
		remaining -=112;
		while(remaining>=112){	
			cipher_blks[0]  = gen_logging_blk((block*)log_msg, counter+1); 
			gen_7_blks(cipher_blks,log_msg,counter);
			AES_ECB_8(cipher_blks,sched, mask);
			tag_blks_xor_8(tag_blks,cipher_blks);
			counter +=8;
			log_msg +=110;
			remaining -=112;
		}
	}//end of nblks

	if(remaining >=56){//4-block, 4*14=56 bytes log data
		cmpt_4_blks(cipher_blks,counter, log_msg, sched, mask);
		tag_blks[0] = xor_block( xor_block(cipher_blks[0], cipher_blks[1]), xor_block(cipher_blks[2], cipher_blks[3]));  
		tag_blks[2] = xor_block(tag_blks[2], tag_blks[0]);
		remaining -= 56;
		counter +=4;
		log_msg +=54;/*56-byte computed, apply 54-byte, leaving 2-byte overwrote by counter*/
	}
	if (remaining >= 28) {//2-block, 2*14=28 bytes log data
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
		aes_single(cipher_blks, sched,mask);
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
		while(remaining--){
			tmp.u8[remaining+1]=log_msg[remaining-1];
		}
		tmp.bl = xor_block(tmp.bl, mask);
		aes_single(cipher_blks, sched, mask);
		tag_blks[2] = xor_block(tag_blks[2], tmp.bl);	
	}
    
	out.bl = _mm_loadu_si128((block*)&tag_blks[2]);
	return out.u64[0];
}



/** Initial:
*** Expand AES round keys
*** Generate  key-state pairs for signing 
***/
static void quickmod_int(void){
	block * sched_key;
	s_0 = _mm_setr_epi32(0x0001, 0x0000, 0x0000, 0x0000);
	AES_128_Key_Expansion(aeskey,&const_aeskey); //expand aes round keys
	sched_key = ((block *)(const_aeskey.rd_key)); //point to AES round keys
	my_update(&signing_pair[0], &s_0,  sched_key);
}

#undef gen_7_blks
#undef prernd_8
#undef prernd_4
#undef enc_2
#undef enc_4
#undef enc_8
#undef AES_ECB_2
#undef AES_ECB_4
#undef AES_ECB_8
#undef tag_blks_xor_8

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
    unsigned long long temp;
    qsort(x, n, sizeof(unsigned long long), compare);

    if(n%2==0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        return ((x[n/2] + x[n/2 - 1]) / 2.0);
    } else {
        // else return the element in the middle
        return  x[n/2];
    }
}
//*****************************************************************


int main(int argc, char* argv[]){
	
	int i,j,k;
	uint64_t  stag[8], vtag[8];
	block  current_pair[16];
	struct timespec start, end;
	clockid_t id = CLOCK_MONOTONIC;
	unsigned long long my_med;
	block * sched_key = ((block *)(const_aeskey.rd_key)); //point to AES round keys
	
	unsigned long long  mean, my_sd, sd_sum, sum;
	
	if (argc >=2) len = atoi(argv[1]);
    else len = 256;

	//initial log messages------------
	char str[4112];
	char str1[4112];
	char str2[4112];
	char str3[4112];
	char str4[4112];
	char str5[4112];
	char str6[4112];
	char str7[4112];
	memset(str,'a',(len));
	memset(str1,'b',(len));
	memset(str2,'c',(len));
	memset(str3,'d',(len));
	memset(str4,'e',(len));
	memset(str5,'f',(len));
	memset(str6,'g',(len));
	memset(str7,'h',(len));

	quickmod_int();
	sleep(0.5);

	for(j=0;j<10;j++){
		for(i=0;i<ITERATIONS;i++){
			/*Generating 8 signing keys*/
			my_update(&current_pair[0], &s_0,  sched_key);
			my_update(&current_pair[2], &current_pair[0],  sched_key);
			my_update(&current_pair[4], &current_pair[2],  sched_key);
			my_update(&current_pair[6], &current_pair[4],  sched_key);
			my_update(&current_pair[8], &current_pair[6],  sched_key);
			my_update(&current_pair[10], &current_pair[8], sched_key);
			my_update(&current_pair[12], &current_pair[10],sched_key);
			my_update(&current_pair[14], &current_pair[12],sched_key);

			/*Computing 8 messages*/
			stag[0]=sign_core((unsigned char*)str, &len, &current_pair[1]);
			stag[1]=sign_core((unsigned char*)str1, &len, &current_pair[3]);
			stag[2]=sign_core((unsigned char*)str2, &len, &current_pair[5]);
			stag[3]=sign_core((unsigned char*)str3, &len, &current_pair[7]);
			stag[4]=sign_core((unsigned char*)str4, &len, &current_pair[9]);
			stag[5]=sign_core((unsigned char*)str5, &len, &current_pair[11]);
			stag[6]=sign_core((unsigned char*)str6, &len, &current_pair[13]);
			stag[7]=sign_core((unsigned char*)str7, &len, &current_pair[15]);

			clock_gettime(id, &start);
			/*Generating 8 signing keys*/
			my_update(&current_pair[0], &s_0,  sched_key);
			my_update(&current_pair[2], &current_pair[0],  sched_key);
			my_update(&current_pair[4], &current_pair[2],  sched_key);
			my_update(&current_pair[6], &current_pair[4],  sched_key);
			my_update(&current_pair[8], &current_pair[6],  sched_key);
			my_update(&current_pair[10], &current_pair[8], sched_key);
			my_update(&current_pair[12], &current_pair[10],sched_key);
			my_update(&current_pair[14], &current_pair[12],sched_key);

			/*Computing 8 messages*/
			vtag[0]=verify_core((unsigned char*)str, &len, &current_pair[1]);
			vtag[1]=verify_core((unsigned char*)str1, &len, &current_pair[3]);
			vtag[2]=verify_core((unsigned char*)str2, &len, &current_pair[5]);
			vtag[3]=verify_core((unsigned char*)str3, &len, &current_pair[7]);
			vtag[4]=verify_core((unsigned char*)str4, &len, &current_pair[9]);
			vtag[5]=verify_core((unsigned char*)str5, &len, &current_pair[11]);
			vtag[6]=verify_core((unsigned char*)str6, &len, &current_pair[13]);
			vtag[7]=verify_core((unsigned char*)str7, &len, &current_pair[15]);

			for(k=0;k<8;k++){
				if(vtag[k]!=stag[k])printf("tag verfication fail!\n");break;
			}

			clock_gettime(id,&end);
			my_time[i] = ( (unsigned long long)(end.tv_sec - start.tv_sec))*1000000000 + (end.tv_nsec - start.tv_nsec);
			
		}

		quick_med[j] =  median(ITERATIONS,  my_time);
		sleep(0.5);
	} 
	sum =0;
	for(i=0;i<10;i++) sum +=quick_med[i];
	mean = (sum/10)/8;
	sd_sum =0;
	for(i=0;i<10;i++) sd_sum +=(quick_med[i]/8-mean)*(quick_med[i]/8-mean);
	my_sd = sd_sum/10;
	my_sd = sqrt(my_sd); 

	printf("	      -[QuickLog Verify]-: median time = %lld ns, standard deviation =%lld \n", ((unsigned long long) (quick_med[0]/8)), my_sd);

	return 0;

}
